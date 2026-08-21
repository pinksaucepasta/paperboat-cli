//go:build windows

package windowsopenssh

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

const qualificationAddress = "127.0.0.1"

func qualifyNative(ctx context.Context, config Config, result Result) (report QualificationReport, err error) {
	report.Port = result.Port
	identity, identityErr := currentWindowsSSHIdentity()
	if identityErr != nil {
		return report, qualificationFailure(QualificationStageSetup, identityErr, nil)
	}
	report.Identity = identity

	for _, path := range []string{result.SSHPath, result.SSHDPath, result.SCPPath, result.SFTPClientPath, result.SFTPPath, result.KeygenPath} {
		if verifyErr := verifyBinary(ctx, config, path); verifyErr != nil {
			return report, qualificationFailure(QualificationStageSetup, verifyErr, nil, config.InstallRoot)
		}
	}

	temporaryRoot, tempErr := os.MkdirTemp("", "paperboat-openssh-qualification-")
	if tempErr != nil {
		return report, qualificationFailure(QualificationStageSetup, tempErr, nil)
	}
	cleanup := &qualificationCleanup{
		config:         config,
		result:         result,
		identity:       identity,
		temporaryRoot:  temporaryRoot,
		temporaryFiles: make([]string, 0, 8),
		remoteFiles:    make(map[string]bool),
	}
	defer func() {
		cleanupErr := cleanup.run(ctx, &report)
		if cleanupErr != nil {
			if err == nil {
				err = cleanupErr
			} else {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()

	keyID, randomErr := qualificationRandomID()
	if randomErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, randomErr, nil)
	}
	privateKey := filepath.Join(temporaryRoot, "qualification-"+keyID)
	publicKey := privateKey + ".pub"
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, privateKey, publicKey)
	keygen, keygenErr := runQualificationCommand(ctx, config, result.KeygenPath, "-q", "-t", "ed25519", "-N", "", "-f", privateKey)
	if keygenErr != nil || keygen.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageEnrollment, keygenErr, keygen.ExitCode, keygen.Output, temporaryRoot)
	}
	keyLine, readKeyErr := os.ReadFile(publicKey)
	if readKeyErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, readKeyErr, nil, temporaryRoot)
	}
	keyLine = bytes.TrimSpace(keyLine)
	if keyErr := validateAuthorizedKeyLine(keyLine); keyErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, keyErr, nil, temporaryRoot)
	}
	privateMaterial, privateReadErr := os.ReadFile(privateKey)
	if privateReadErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, privateReadErr, nil, temporaryRoot)
	}
	keySigner, signerErr := ssh.ParsePrivateKey(privateMaterial)
	if signerErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, signerErr, nil, privateKey, temporaryRoot)
	}

	authorizedPath := filepath.Join(config.StateRoot, "authorized_keys", "paperboat")
	enrollment, enrollErr := enrollEphemeralAuthorizedKey(authorizedPath, keyLine)
	if enrollErr != nil {
		return report, qualificationFailure(QualificationStageEnrollment, enrollErr, nil, config.StateRoot, temporaryRoot)
	}
	cleanup.enrollment = enrollment

	knownHosts, hostKeyErr := writeQualificationKnownHosts(config, result, temporaryRoot)
	if hostKeyErr != nil {
		return report, qualificationFailure(QualificationStageSetup, hostKeyErr, nil, config.StateRoot, temporaryRoot)
	}
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, knownHosts)
	cleanup.privateKey = privateKey
	cleanup.knownHosts = knownHosts
	pinnedHostKey, pinnedHostKeyErr := readQualificationHostKey(config)
	if pinnedHostKeyErr != nil {
		return report, qualificationFailure(QualificationStageSetup, pinnedHostKeyErr, nil, config.StateRoot, temporaryRoot)
	}

	commonSSH := qualificationSSHArgs(privateKey, knownHosts, result.Port)
	target := identity + "@" + qualificationAddress

	authArgs := append([]string{}, commonSSH...)
	authArgs = append(authArgs, "-T", target, `powershell.exe -NoLogo -NoProfile -NonInteractive -Command "exit 0"`)
	authResult, authErr := runQualificationCommand(ctx, config, result.SSHPath, authArgs...)
	if authErr != nil || authResult.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageAuth, authErr, authResult.ExitCode, authResult.Output, privateKey, knownHosts, temporaryRoot, identity)
	}
	report.Authenticated = true
	cleanup.authenticated = true

	protocolClient, protocolErr := qualificationSSHClient(ctx, net.JoinHostPort(qualificationAddress, strconv.Itoa(int(result.Port))), identity, keySigner, pinnedHostKey)
	if protocolErr != nil {
		return report, qualificationFailure(QualificationStageExec, protocolErr, nil, temporaryRoot, identity)
	}
	cleanup.protocolClient = protocolClient
	execMarker := "PAPERBOAT_OPENSSH_EXEC_" + keyID
	execOutput, execStatus, execErr := qualificationSSHExec(protocolClient, `echo `+execMarker, false)
	if execErr != nil || execStatus != 0 || !bytes.Contains(execOutput, []byte(execMarker)) {
		return report, qualificationFailureWithCode(QualificationStageExec, execErr, execStatus, execOutput, temporaryRoot, identity)
	}
	report.Exec = true

	_, status, exitErr := qualificationSSHExec(protocolClient, `exit `+strconv.Itoa(qualificationExpectedExit), false)
	if exitErr == nil && status != qualificationExpectedExit {
		exitErr = fmt.Errorf("SSH exit status = %d, want %d", status, qualificationExpectedExit)
	}
	if exitErr != nil {
		return report, qualificationFailure(QualificationStageExitStatus, exitErr, nil, temporaryRoot, identity)
	}
	report.ExitStatus = true

	ptyMarker := "PAPERBOAT_OPENSSH_PTY_" + keyID
	ptyOutput, ptyErr := qualificationSSHShellMarker(protocolClient, ptyMarker)
	if ptyErr != nil {
		return report, qualificationFailureWithCode(QualificationStagePTY, ptyErr, -1, ptyOutput, temporaryRoot, identity)
	}
	report.PTY = true

	scpUploadPath := filepath.Join(temporaryRoot, "scp-upload.bin")
	scpDownloadPath := filepath.Join(temporaryRoot, "scp-download.bin")
	scpPayload := []byte("paperboat native OpenSSH scp qualification\n" + keyID + "\n")
	if writeErr := os.WriteFile(scpUploadPath, scpPayload, 0o600); writeErr != nil {
		return report, qualificationFailure(QualificationStageSCPUpload, writeErr, nil, temporaryRoot)
	}
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, scpUploadPath, scpDownloadPath)
	scpRemote := "paperboat-qualification-scp-" + keyID
	scpUploadArgs := qualificationSCPArgs(privateKey, knownHosts, result.Port)
	scpUploadArgs = append(scpUploadArgs, "-O", scpUploadPath, target+":"+scpRemote)
	scpUpload, scpUploadErr := runQualificationCommand(ctx, config, result.SCPPath, scpUploadArgs...)
	if scpUploadErr != nil || scpUpload.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageSCPUpload, scpUploadErr, scpUpload.ExitCode, scpUpload.Output, privateKey, knownHosts, temporaryRoot, identity)
	}
	cleanup.remoteFiles[scpRemote] = true
	report.SCPUpload = true
	scpDownloadArgs := qualificationSCPArgs(privateKey, knownHosts, result.Port)
	scpDownloadArgs = append(scpDownloadArgs, "-O", target+":"+scpRemote, scpDownloadPath)
	scpDownload, scpDownloadErr := runQualificationCommand(ctx, config, result.SCPPath, scpDownloadArgs...)
	if scpDownloadErr != nil || scpDownload.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageSCPDownload, scpDownloadErr, scpDownload.ExitCode, scpDownload.Output, privateKey, knownHosts, temporaryRoot, identity)
	}
	if downloaded, readErr := os.ReadFile(scpDownloadPath); readErr != nil || !bytes.Equal(downloaded, scpPayload) {
		return report, qualificationFailure(QualificationStageSCPDownload, readErrOrMismatch(readErr), nil, temporaryRoot)
	}
	report.SCPDownload = true

	sftpUploadPath := filepath.Join(temporaryRoot, "sftp-upload.bin")
	sftpDownloadPath := filepath.Join(temporaryRoot, "sftp-download.bin")
	sftpPayload := []byte("paperboat native OpenSSH sftp qualification\n" + keyID + "\n")
	if writeErr := os.WriteFile(sftpUploadPath, sftpPayload, 0o600); writeErr != nil {
		return report, qualificationFailure(QualificationStageSFTPUpload, writeErr, nil, temporaryRoot)
	}
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, sftpUploadPath, sftpDownloadPath)
	sftpRemote := "paperboat-qualification-sftp-" + keyID
	sftpUploadBatch := filepath.Join(temporaryRoot, "sftp-upload.batch")
	if batchErr := writeSFTPBatch(sftpUploadBatch, "put "+quoteSFTPPath(sftpUploadPath)+" "+quoteSFTPPath(sftpRemote)); batchErr != nil {
		return report, qualificationFailure(QualificationStageSFTPUpload, batchErr, nil, temporaryRoot)
	}
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, sftpUploadBatch)
	sftpUploadArgs := qualificationSFTPArgs(privateKey, knownHosts, result.Port, sftpUploadBatch, target)
	sftpUpload, sftpUploadErr := runQualificationCommand(ctx, config, result.SFTPClientPath, sftpUploadArgs...)
	if sftpUploadErr != nil || sftpUpload.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageSFTPUpload, sftpUploadErr, sftpUpload.ExitCode, sftpUpload.Output, privateKey, knownHosts, temporaryRoot, identity)
	}
	cleanup.remoteFiles[sftpRemote] = true
	report.SFTPUpload = true

	sftpDownloadBatch := filepath.Join(temporaryRoot, "sftp-download.batch")
	if batchErr := writeSFTPBatch(sftpDownloadBatch, "get "+quoteSFTPPath(sftpRemote)+" "+quoteSFTPPath(sftpDownloadPath)); batchErr != nil {
		return report, qualificationFailure(QualificationStageSFTPDownload, batchErr, nil, temporaryRoot)
	}
	cleanup.temporaryFiles = append(cleanup.temporaryFiles, sftpDownloadBatch)
	sftpDownloadArgs := qualificationSFTPArgs(privateKey, knownHosts, result.Port, sftpDownloadBatch, target)
	sftpDownload, sftpDownloadErr := runQualificationCommand(ctx, config, result.SFTPClientPath, sftpDownloadArgs...)
	if sftpDownloadErr != nil || sftpDownload.ExitCode != 0 {
		return report, qualificationFailureWithCode(QualificationStageSFTPDownload, sftpDownloadErr, sftpDownload.ExitCode, sftpDownload.Output, privateKey, knownHosts, temporaryRoot, identity)
	}
	if downloaded, readErr := os.ReadFile(sftpDownloadPath); readErr != nil || !bytes.Equal(downloaded, sftpPayload) {
		return report, qualificationFailure(QualificationStageSFTPDownload, readErrOrMismatch(readErr), nil, temporaryRoot)
	}
	report.SFTPDownload = true
	return report, nil
}

type qualificationCleanup struct {
	config         Config
	result         Result
	identity       string
	temporaryRoot  string
	privateKey     string
	knownHosts     string
	temporaryFiles []string
	remoteFiles    map[string]bool
	authenticated  bool
	enrollment     *authorizedKeysEnrollment
	protocolClient *ssh.Client
}

func (c *qualificationCleanup) run(_ context.Context, report *QualificationReport) error {
	var failures []error
	if c.authenticated {
		cleanupContext, cancel := context.WithTimeout(context.Background(), qualificationCleanupTimeout)
		defer cancel()
		for remote := range c.remoteFiles {
			if c.protocolClient != nil {
				_, status, commandErr := qualificationSSHExec(c.protocolClient, `del /f /q `+remote, false)
				if commandErr == nil && status == 0 {
					continue
				}
			}
			args := qualificationSSHArgs(c.privateKey, c.knownHosts, c.result.Port)
			args = append(args, "-T", c.identity+"@"+qualificationAddress, qualificationPowerShellCommand(`Remove-Item -LiteralPath '`+remote+`' -Force; exit 0`))
			command, commandErr := runQualificationCommand(cleanupContext, c.config, c.result.SSHPath, args...)
			if commandErr != nil || command.ExitCode != 0 {
				failures = append(failures, qualificationFailureWithCode(QualificationStageCleanup, commandErr, command.ExitCode, command.Output, c.config.StateRoot, c.temporaryRoot, c.identity))
			}
		}
	}
	if c.protocolClient != nil {
		_ = c.protocolClient.Close()
	}
	if c.enrollment != nil {
		if restoreErr := c.enrollment.Restore(); restoreErr != nil {
			failures = append(failures, qualificationFailure(QualificationStageRestore, restoreErr, nil, c.config.StateRoot, c.temporaryRoot))
		} else {
			report.Restored = true
		}
	}
	if removeErr := removeQualificationTree(c.temporaryRoot, c.temporaryFiles); removeErr != nil {
		failures = append(failures, qualificationFailure(QualificationStageCleanup, removeErr, nil, c.temporaryRoot))
	} else {
		report.TemporaryStateRemoved = true
	}
	if len(failures) == 0 {
		return nil
	}
	return errors.Join(failures...)
}

// Windows OpenSSH passes remote commands through the configured default shell.
// EncodedCommand avoids the nested cmd.exe/PowerShell quoting rules and keeps
// command exit status deterministic on both PowerShell 5.1 and PowerShell 7 hosts.
func qualificationPowerShellCommand(script string) string {
	codeUnits := utf16.Encode([]rune(script))
	encoded := make([]byte, len(codeUnits)*2)
	for index, codeUnit := range codeUnits {
		binary.LittleEndian.PutUint16(encoded[index*2:], codeUnit)
	}
	return `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ` + base64.StdEncoding.EncodeToString(encoded)
}

func currentWindowsSSHIdentity() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("PAPERBOAT_WINDOWS_SSH_IDENTITY")); configured != "" {
		if !validWindowsSSHIdentity(configured) {
			return "", fmt.Errorf("invalid configured Windows SSH identity")
		}
		return configured, nil
	}
	account, err := user.Current()
	if err != nil || account == nil {
		return "", errors.Join(ErrQualification, err)
	}
	identity := strings.TrimSpace(account.Username)
	if !validWindowsSSHIdentity(identity) {
		return "", fmt.Errorf("invalid current Windows identity")
	}
	return identity, nil
}

func validWindowsSSHIdentity(value string) bool {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\t @/:\"'") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func qualificationRandomID() (string, error) {
	var value [12]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func writeQualificationKnownHosts(config Config, result Result, root string) (string, error) {
	public, _, err := readQualificationHostKeyMaterial(config)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "known_hosts")
	line := fmt.Sprintf("[%s]:%d %s\n", qualificationAddress, result.Port, string(public))
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func readQualificationHostKey(config Config) (ssh.PublicKey, error) {
	_, key, err := readQualificationHostKeyMaterial(config)
	return key, err
}

func readQualificationHostKeyMaterial(config Config) ([]byte, ssh.PublicKey, error) {
	public, err := os.ReadFile(filepath.Join(config.StateRoot, "hostkeys", "ssh_host_ed25519_key.pub"))
	if err != nil {
		return nil, nil, err
	}
	public = bytes.TrimSpace(public)
	key, _, _, rest, err := ssh.ParseAuthorizedKey(append(append([]byte(nil), public...), '\n'))
	if err != nil || key == nil || len(bytes.TrimSpace(rest)) != 0 || key.Type() != "ssh-ed25519" {
		return nil, nil, errors.New("invalid Paperboat host public key")
	}
	return public, key, nil
}

func qualificationSSHArgs(privateKey, knownHosts string, port uint16) []string {
	return []string{
		"-q", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts, "-o", "GlobalKnownHostsFile=none",
		"-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", "-o", "LogLevel=ERROR", "-i", privateKey,
		"-p", strconv.Itoa(int(port)),
	}
}

func qualificationSCPArgs(privateKey, knownHosts string, port uint16) []string {
	args := qualificationSSHArgs(privateKey, knownHosts, port)
	for index := range args {
		if args[index] == "-p" {
			args[index] = "-P"
		}
	}
	return args
}

func qualificationSFTPArgs(privateKey, knownHosts string, port uint16, batch, target string) []string {
	args := qualificationSSHArgs(privateKey, knownHosts, port)
	for index := range args {
		if args[index] == "-p" {
			args[index] = "-P"
		}
	}
	return append(args, "-b", batch, target)
}

func writeSFTPBatch(path, command string) error {
	if !filepath.IsAbs(path) || command == "" || strings.ContainsAny(command, "\x00\r\n") {
		return ErrInvalidConfig
	}
	return os.WriteFile(path, []byte(command+"\n"), 0o600)
}

func readErrOrMismatch(err error) error {
	if err != nil {
		return err
	}
	return errors.New("downloaded payload does not match uploaded payload")
}

func removeQualificationTree(root string, files []string) error {
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "paperboat-openssh-qualification-") {
		return ErrInvalidConfig
	}
	var failures []error
	for _, path := range files {
		if path == "" {
			continue
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			failures = append(failures, errors.New("qualification temporary path escapes temporary root"))
			continue
		}
		if err := wipeQualificationFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if err := os.RemoveAll(root); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func wipeQualificationFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("qualification temporary path is not a regular file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		zeros := make([]byte, 32*1024)
		remaining := info.Size()
		for remaining > 0 {
			chunk := int64(len(zeros))
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := file.Write(zeros[:chunk]); err != nil {
				_ = file.Close()
				return err
			}
			remaining -= chunk
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

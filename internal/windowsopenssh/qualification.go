package windowsopenssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/crypto/ssh"
)

const (
	qualificationCommandTimeout = 45 * time.Second
	qualificationCleanupTimeout = 20 * time.Second
	qualificationMaximumDetail  = 2048
	qualificationExpectedExit   = 37
)

var (
	ErrQualification                = errors.New("Windows OpenSSH qualification failed")
	ErrQualificationEnrollment      = errors.New("Windows OpenSSH ephemeral key enrollment failed")
	ErrQualificationAuth            = errors.New("Windows OpenSSH public-key authentication failed")
	ErrQualificationExec            = errors.New("Windows OpenSSH noninteractive exec failed")
	ErrQualificationExitStatus      = errors.New("Windows OpenSSH exit-status verification failed")
	ErrQualificationPTY             = errors.New("Windows OpenSSH PTY verification failed")
	ErrQualificationSCP             = errors.New("Windows OpenSSH scp verification failed")
	ErrQualificationSFTP            = errors.New("Windows OpenSSH sftp verification failed")
	ErrQualificationRestore         = errors.New("Windows OpenSSH ephemeral key restoration failed")
	ErrQualificationRestoreConflict = errors.New("Windows OpenSSH authorized-keys restoration conflict")
	ErrQualificationCleanup         = errors.New("Windows OpenSSH qualification cleanup failed")
)

type QualificationStage string

const (
	QualificationStageSetup        QualificationStage = "setup"
	QualificationStageEnrollment   QualificationStage = "enrollment"
	QualificationStageAuth         QualificationStage = "public_key_authentication"
	QualificationStageExec         QualificationStage = "noninteractive_exec"
	QualificationStageExitStatus   QualificationStage = "exit_status"
	QualificationStagePTY          QualificationStage = "pty"
	QualificationStageSCPUpload    QualificationStage = "scp_upload"
	QualificationStageSCPDownload  QualificationStage = "scp_download"
	QualificationStageSFTPUpload   QualificationStage = "sftp_upload"
	QualificationStageSFTPDownload QualificationStage = "sftp_download"
	QualificationStageRestore      QualificationStage = "restore"
	QualificationStageCleanup      QualificationStage = "cleanup"
)

// QualificationError is deliberately small and safe to return to CLI, logs, and
// JSON callers. It never includes command arguments, key material, or an
// unbounded native-process transcript.
type QualificationError struct {
	Stage    QualificationStage `json:"stage"`
	ExitCode int                `json:"exit_code,omitempty"`
	Detail   string             `json:"detail,omitempty"`
	Cause    error              `json:"-"`
}

func (e *QualificationError) Error() string {
	if e == nil {
		return ErrQualification.Error()
	}
	message := fmt.Sprintf("%s: %s", ErrQualification, e.Stage)
	if e.ExitCode >= 0 {
		message += fmt.Sprintf(" (exit code %d)", e.ExitCode)
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

func (e *QualificationError) Unwrap() error {
	if e == nil || e.Cause == nil {
		return ErrQualification
	}
	return errors.Join(ErrQualification, e.Cause)
}

// QualificationReport is safe to persist as release evidence. It contains no
// private paths, credentials, host keys, or native command output.
type QualificationReport struct {
	Identity              string `json:"identity"`
	Port                  uint16 `json:"port"`
	Authenticated         bool   `json:"authenticated"`
	Exec                  bool   `json:"exec"`
	ExitStatus            bool   `json:"exit_status"`
	PTY                   bool   `json:"pty"`
	SCPUpload             bool   `json:"scp_upload"`
	SCPDownload           bool   `json:"scp_download"`
	SFTPUpload            bool   `json:"sftp_upload"`
	SFTPDownload          bool   `json:"sftp_download"`
	Restored              bool   `json:"restored"`
	TemporaryStateRemoved bool   `json:"temporary_state_removed"`
}

// Qualify runs the complete post-setup qualification against the Paperboat
// loopback service. The native implementation is Windows-only; all callers
// still receive the same typed contract on other platforms.
func Qualify(ctx context.Context, config Config, result Result) (QualificationReport, error) {
	if ctx == nil {
		return QualificationReport{}, qualificationFailure(QualificationStageSetup, ErrInvalidConfig, nil)
	}
	if err := validateQualificationResult(config, result); err != nil {
		return QualificationReport{}, qualificationFailure(QualificationStageSetup, err, nil)
	}
	return qualifyNative(ctx, config, result)
}

func validateQualificationResult(config Config, result Result) error {
	if err := validate(config); err != nil {
		return err
	}
	expected := resultForConfig(config)
	if result.PackageID != PackageID || result.Version != config.ApprovedVersion || result.Port != config.Port ||
		!sameCleanPath(result.SSHPath, expected.SSHPath) || !sameCleanPath(result.SSHDPath, expected.SSHDPath) ||
		!sameCleanPath(result.SCPPath, expected.SCPPath) || !sameCleanPath(result.SFTPClientPath, expected.SFTPClientPath) ||
		!sameCleanPath(result.SFTPPath, expected.SFTPPath) || !sameCleanPath(result.KeygenPath, expected.KeygenPath) {
		return ErrInvalidConfig
	}
	return nil
}

func qualificationFailure(stage QualificationStage, cause error, output []byte, secrets ...string) error {
	detail := redactQualificationOutput(output, secrets...)
	exitCode := qualificationExitCode(cause)
	if exitCode < 0 {
		exitCode = 0
	}
	return &QualificationError{Stage: stage, ExitCode: exitCode, Detail: detail, Cause: errors.Join(stageCause(stage), cause)}
}

func qualificationFailureWithCode(stage QualificationStage, cause error, exitCode int, output []byte, secrets ...string) error {
	detail := redactQualificationOutput(output, secrets...)
	return &QualificationError{Stage: stage, ExitCode: exitCode, Detail: detail, Cause: errors.Join(stageCause(stage), cause)}
}

func stageCause(stage QualificationStage) error {
	switch stage {
	case QualificationStageEnrollment:
		return ErrQualificationEnrollment
	case QualificationStageAuth:
		return ErrQualificationAuth
	case QualificationStageExec:
		return ErrQualificationExec
	case QualificationStageExitStatus:
		return ErrQualificationExitStatus
	case QualificationStagePTY:
		return ErrQualificationPTY
	case QualificationStageSCPUpload, QualificationStageSCPDownload:
		return ErrQualificationSCP
	case QualificationStageSFTPUpload, QualificationStageSFTPDownload:
		return ErrQualificationSFTP
	case QualificationStageRestore:
		return ErrQualificationRestore
	case QualificationStageCleanup:
		return ErrQualificationCleanup
	default:
		return ErrQualification
	}
}

func redactQualificationOutput(output []byte, secrets ...string) string {
	value := string(bytes.TrimSpace(output))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, "<redacted>")
		value = strings.ReplaceAll(value, filepath.ToSlash(secret), "<redacted>")
	}
	value = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	if len(value) > qualificationMaximumDetail {
		value = value[:qualificationMaximumDetail] + "…"
	}
	return value
}

func qualificationExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ProcessState != nil {
		return exitErr.ExitCode()
	}
	return -1
}

type qualificationCommandResult struct {
	Output   []byte
	ExitCode int
}

func runQualificationCommand(ctx context.Context, config Config, path string, args ...string) (qualificationCommandResult, error) {
	if ctx == nil || config.Runner == nil || !filepath.IsAbs(path) {
		return qualificationCommandResult{ExitCode: -1}, ErrInvalidConfig
	}
	commandCtx, cancel := context.WithTimeout(ctx, qualificationCommandTimeout)
	defer cancel()
	output, err := config.Runner.Run(commandCtx, path, args...)
	result := qualificationCommandResult{Output: output, ExitCode: qualificationExitCode(err)}
	if commandCtx.Err() != nil {
		return result, commandCtx.Err()
	}
	return result, err
}

type authorizedKeysEnrollment struct {
	path             string
	original         []byte
	originalExists   bool
	originalMode     fs.FileMode
	originalSecurity qualificationSecurity
	expected         []byte
	restored         bool
	unlock           func()
}

func enrollEphemeralAuthorizedKey(path string, keyLine []byte) (*authorizedKeysEnrollment, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.Join(ErrQualificationEnrollment, ErrInvalidConfig)
	}
	if err := validateQualificationFile(path, true); err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	if err := validateAuthorizedKeyLine(keyLine); err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	stateRoot := filepath.Dir(filepath.Dir(path))
	unlock, err := lockAuthorizedKeys(stateRoot)
	if err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	release := true
	defer func() {
		if release {
			unlock()
		}
	}()
	original, exists, mode, err := readQualificationFile(path)
	if err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	security, err := captureQualificationSecurity(path, exists)
	if err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	next, err := appendAuthorizedKey(original, keyLine)
	if err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	enrollment := &authorizedKeysEnrollment{
		path:             path,
		original:         original,
		originalExists:   exists,
		originalMode:     mode,
		originalSecurity: security,
		expected:         next,
		unlock:           unlock,
	}
	if err := atomicfile.Write(path, next, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return nil, errors.Join(ErrQualificationEnrollment, err)
	}
	current, currentExists, _, readErr := readQualificationFile(path)
	if readErr != nil || !currentExists || !bytes.Equal(current, next) {
		restoreErr := enrollment.Restore()
		return nil, errors.Join(ErrQualificationEnrollment, readErr, ErrQualificationRestoreConflict, restoreErr)
	}
	release = false
	return enrollment, nil
}

func (e *authorizedKeysEnrollment) Restore() error {
	if e == nil || e.restored {
		return nil
	}
	defer func() {
		if e.unlock != nil {
			e.unlock()
			e.unlock = nil
		}
	}()
	current, exists, _, err := readQualificationFile(e.path)
	if err != nil {
		return errors.Join(ErrQualificationRestore, err)
	}
	if !exists || !bytes.Equal(current, e.expected) {
		return errors.Join(ErrQualificationRestore, ErrQualificationRestoreConflict)
	}
	if e.originalExists {
		mode := e.originalMode.Perm()
		if mode == 0 {
			mode = 0o600
		}
		if err := atomicfile.Write(e.path, e.original, atomicfile.Options{Mode: mode, OwnerUID: -1, OwnerGID: -1}); err != nil {
			return errors.Join(ErrQualificationRestore, err)
		}
		if err := restoreQualificationSecurity(e.path, e.originalSecurity); err != nil {
			return errors.Join(ErrQualificationRestore, err)
		}
	} else {
		if err := validateQualificationFile(e.path, false); err != nil {
			return errors.Join(ErrQualificationRestore, err)
		}
		if err := os.Remove(e.path); err != nil {
			return errors.Join(ErrQualificationRestore, err)
		}
	}
	final, finalExists, _, err := readQualificationFile(e.path)
	if err != nil || finalExists != e.originalExists || e.originalExists && !bytes.Equal(final, e.original) {
		return errors.Join(ErrQualificationRestore, err, ErrQualificationRestoreConflict)
	}
	e.restored = true
	return nil
}

func readQualificationFile(path string) ([]byte, bool, fs.FileMode, error) {
	if err := validateQualificationFile(path, true); err != nil {
		return nil, false, 0, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, 0o600, nil
	}
	if err != nil {
		return nil, false, 0, err
	}
	value, err := os.ReadFile(path)
	return value, true, info.Mode(), err
}

func appendAuthorizedKey(original, keyLine []byte) ([]byte, error) {
	line := bytes.TrimSpace(keyLine)
	if err := validateAuthorizedKeyLine(line); err != nil {
		return nil, err
	}
	for _, existing := range bytes.Split(original, []byte{'\n'}) {
		if bytes.Equal(bytes.TrimSpace(existing), line) {
			return nil, errors.New("ephemeral key is already enrolled")
		}
	}
	next := append([]byte(nil), original...)
	if len(next) > 0 && next[len(next)-1] != '\n' {
		next = append(next, '\n')
	}
	next = append(next, line...)
	next = append(next, '\n')
	return next, nil
}

func validateAuthorizedKeyLine(line []byte) error {
	if len(line) == 0 || strings.ContainsAny(string(line), "\r\n\x00") {
		return errors.New("invalid authorized key line")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(append(append([]byte(nil), line...), '\n'))
	if err != nil || key == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid authorized key line")
	}
	return nil
}

func validQualificationRemoteName(value string) bool {
	if len(value) <= len("paperboat-qualification-") || len(value) > 128 ||
		!strings.HasPrefix(value, "paperboat-qualification-") {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

func quoteSFTPPath(path string) string {
	path = filepath.ToSlash(path)
	path = strings.ReplaceAll(path, `\`, `\\`)
	path = strings.ReplaceAll(path, `"`, `\"`)
	return `"` + path + `"`
}

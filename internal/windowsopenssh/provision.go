package windowsopenssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/processlaunch"
)

const (
	MinimumWingetVersion = "1.7.0"
	ServiceName          = "PaperboatSshd"
	securityModuleImport = "$m=Join-Path $env:WINDIR 'System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1';Import-Module -Name $m -ErrorAction Stop;"
)

var (
	ErrInvalidConfig        = errors.New("invalid Windows OpenSSH configuration")
	ErrInstallerUnavailable = errors.New("openssh_installer_unavailable")
	ErrInstallFailed        = errors.New("openssh_install_failed")
	ErrUntrustedBinary      = errors.New("openssh_binary_untrusted")
	ErrVersionMismatch      = errors.New("openssh_version_mismatch")
	ErrConflictingInstall   = errors.New("openssh_conflicting_installation")
	ErrRepairFailed         = errors.New("openssh_repair_failed")
	ErrServiceUnhealthy     = errors.New("openssh_service_unhealthy")
	ErrServiceOwnership     = errors.New("openssh_service_ownership_conflict")
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	processlaunch.ConfigureBackground(command)
	// Keep stdout and stderr on distinct OS handles. Windows OpenSSH and
	// PowerShell attach stream semantics to those handles; merging them at the
	// process boundary can make an otherwise successful remote command report a
	// failed exit status. We merge only after the child has exited.
	var stdout, stderr bytes.Buffer
	// Supply a real, immediately-closed stdin pipe. A nil standard handle makes
	// the Win32 OpenSSH client leave output-producing exec channels open until
	// our deadline even after the server has sent exit-status.
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	output := append([]byte(nil), stdout.Bytes()...)
	output = append(output, stderr.Bytes()...)
	return output, err
}

type Config struct {
	Platform          string
	Architecture      string
	WingetPath        string
	InstallRoot       string
	StateRoot         string
	ApprovedVersion   string
	ExpectedPublisher string
	OwnerSID          string
	ServiceSID        string
	ServiceExecutable string
	Port              uint16
	Runner            Runner
}

type Result struct {
	PackageID      string
	Version        string
	SSHPath        string
	SSHDPath       string
	SCPPath        string
	SFTPClientPath string
	SFTPPath       string
	KeygenPath     string
	ConfigPath     string
	Port           uint16
}

func DefaultConfig(runner Runner) Config {
	if runner == nil {
		runner = CommandRunner{}
	}
	programFiles := os.Getenv("ProgramFiles")
	programData := os.Getenv("ProgramData")
	// Elevated Windows processes normally inherit these variables, but service
	// repair can be launched from a restricted environment. The documented
	// machine-wide locations remain authoritative in that case.
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return Config{
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		InstallRoot: filepath.Join(programFiles, "OpenSSH"),
		StateRoot:   filepath.Join(programData, "Paperboat", "ssh"), ApprovedVersion: ApprovedVersion,
		ExpectedPublisher: compatibility.ExpectedPublisher, OwnerSID: platformOwnerSID(), ServiceSID: platformServiceSID(), Port: 38222, Runner: runner,
	}
}

func Provision(ctx context.Context, config Config) (Result, error) {
	return provision(ctx, config, false)
}

func provision(ctx context.Context, config Config, force bool) (Result, error) {
	if err := validate(config); err != nil {
		return Result{}, err
	}
	if config.Platform != "windows" {
		return Result{}, ErrInstallerUnavailable
	}
	beforeFirewall, firewallErr := snapshotFirewall(ctx, config)
	if firewallErr != nil {
		return Result{}, firewallErr
	}
	wingetPath := config.WingetPath
	useSystemModule := false
	if wingetPath == "" {
		var err error
		wingetPath, err = resolveWinget(ctx, config.Runner)
		if err != nil {
			if moduleErr := ensureSystemWingetModule(ctx, config.Runner); moduleErr != nil {
				return Result{}, errors.Join(err, moduleErr)
			}
			useSystemModule = true
		}
	}
	if !useSystemModule {
		verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		versionOutput, err := config.Runner.Run(verifyCtx, wingetPath, "--version")
		cancel()
		if err != nil || !supportedWingetVersion(string(versionOutput)) {
			if config.WingetPath != "" {
				return Result{}, errors.Join(ErrInstallerUnavailable, err)
			}
			if moduleErr := ensureSystemWingetModule(ctx, config.Runner); moduleErr != nil {
				return Result{}, errors.Join(ErrInstallerUnavailable, err, moduleErr)
			}
			useSystemModule = true
		}
	}
	if useSystemModule {
		if err := installWithSystemWinget(ctx, config, force); err != nil {
			return Result{}, err
		}
	} else {
		installCtx, cancelInstall := context.WithTimeout(ctx, 10*time.Minute)
		installArgs := []string{
			"install", "--exact", "--id", PackageID, "--version", config.ApprovedVersion,
			"--source", "winget", "--scope", "machine", "--silent",
			"--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity",
		}
		if force {
			installArgs = append(installArgs, "--force")
		}
		output, err := config.Runner.Run(installCtx, wingetPath, installArgs...)
		cancelInstall()
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s", ErrInstallFailed, boundedOutput(output))
		}
	}
	afterFirewall, firewallErr := snapshotFirewall(ctx, config)
	if firewallErr != nil {
		return Result{}, firewallErr
	}
	result := resultForConfig(config)
	for _, path := range []string{result.SSHPath, result.SSHDPath, result.SCPPath, result.SFTPClientPath, result.SFTPPath, result.KeygenPath} {
		if err := verifyBinary(ctx, config, path); err != nil {
			return Result{}, err
		}
	}
	if err := persistFirewallOwnership(ctx, config, beforeFirewall, afterFirewall); err != nil {
		return Result{}, err
	}
	return result, nil
}

func resultForConfig(config Config) Result {
	return Result{
		PackageID:      PackageID,
		Version:        config.ApprovedVersion,
		SSHPath:        filepath.Join(config.InstallRoot, "ssh.exe"),
		SSHDPath:       filepath.Join(config.InstallRoot, "sshd.exe"),
		SCPPath:        filepath.Join(config.InstallRoot, "scp.exe"),
		SFTPClientPath: filepath.Join(config.InstallRoot, "sftp.exe"),
		SFTPPath:       filepath.Join(config.InstallRoot, "sftp-server.exe"),
		KeygenPath:     filepath.Join(config.InstallRoot, "ssh-keygen.exe"),
		ConfigPath:     filepath.Join(config.StateRoot, "sshd_config"),
		Port:           config.Port,
	}
}

func verifyInstalledResult(ctx context.Context, config Config) (Result, error) {
	result := resultForConfig(config)
	for _, path := range []string{result.SSHPath, result.SSHDPath, result.SCPPath, result.SFTPClientPath, result.SFTPPath, result.KeygenPath} {
		if err := verifyBinary(ctx, config, path); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func verifyBinary(ctx context.Context, config Config, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s: %v", ErrUntrustedBinary, path, err)
	}
	escaped := strings.ReplaceAll(path, "'", "''")
	expectedPublisher := strings.ReplaceAll(config.ExpectedPublisher, "'", "''")
	expectedVersion := strings.ReplaceAll(config.ApprovedVersion, "'", "''")
	expectedMachine := "0"
	if config.Architecture == "amd64" {
		expectedMachine = "0x8664"
	} else if config.Architecture == "arm64" {
		expectedMachine = "0xaa64"
	}
	script := securityModuleImport + "$p='" + escaped + "';$s=Get-AuthenticodeSignature -LiteralPath $p;" +
		"$v=(Get-Item -LiteralPath $p).VersionInfo.FileVersion;" +
		"if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notlike '*" + expectedPublisher + "*'){exit 41};" +
		"if($v -notlike '" + expectedVersion + "*'){exit 42};" +
		"if(" + expectedMachine + "-ne 0){$f=[IO.File]::OpenRead($p);try{$r=[IO.BinaryReader]::new($f);$f.Position=0x3c;$o=$r.ReadUInt32();$f.Position=$o+4;$m=$r.ReadUInt16();if($m-ne" + expectedMachine + "){exit 43}}finally{$f.Dispose()}}"
	output, err := config.Runner.Run(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		if bytes.Contains(output, []byte("42")) {
			return ErrVersionMismatch
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %s: verification timed out: %v", ErrUntrustedBinary, path, ctx.Err())
		}
		return fmt.Errorf("%w: %s: %s", ErrUntrustedBinary, path, boundedOutput(output))
	}
	return nil
}

func validate(config Config) error {
	if config.Platform != "windows" || config.Runner == nil || config.WingetPath != "" && strings.TrimSpace(config.WingetPath) == "" || !filepath.IsAbs(config.InstallRoot) ||
		!filepath.IsAbs(config.StateRoot) || config.ApprovedVersion == "" || config.ExpectedPublisher == "" || config.Port == 0 || config.Architecture != "" && !slices.Contains(compatibility.Architectures, config.Architecture) {
		return ErrInvalidConfig
	}
	return nil
}

func resolveWinget(ctx context.Context, runner Runner) (string, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	script := securityModuleImport + "$p=Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop|Sort-Object Version -Descending|Select-Object -First 1;" +
		"$w=Join-Path $p.InstallLocation 'winget.exe';$s=Get-AuthenticodeSignature -LiteralPath $w;" +
		"if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notlike '*Microsoft*'){exit 41};Write-Output $w"
	output, err := runner.Run(resolveCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	path := strings.TrimSpace(string(output))
	if err != nil || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), "winget.exe") {
		return "", errors.Join(ErrInstallerUnavailable, err)
	}
	return filepath.Clean(path), nil
}

func supportedWingetVersion(value string) bool {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	var major, minor int
	if _, err := fmt.Sscanf(value, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 1 || major == 1 && minor >= 7
}

func boundedOutput(value []byte) string {
	value = bytes.TrimSpace(value)
	if len(value) > 2048 {
		value = value[:2048]
	}
	return string(value)
}

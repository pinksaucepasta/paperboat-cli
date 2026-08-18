// Package nativesignature verifies the operating-system signature that binds
// a staged Paperboat executable to a trusted native publisher. TUF establishes
// the release identity; this package is a second, platform-native gate before
// an artifact can be activated.
package nativesignature

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var ErrInvalid = errors.New("native executable signature verification failed")

// Runner is deliberately small so verification behavior can be tested without
// a macOS code-signing identity or a Windows certificate store.
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// CommandRunner invokes a native verification utility without a shell.
type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arguments...).CombinedOutput()
}

// Verifier performs the native checks for a staged target. Linux targets have
// no additional platform signing format in this release; their TUF digest and
// ELF validation remain mandatory. Darwin and Windows both fail closed.
type Verifier struct {
	Runner Runner
}

func New(runner Runner) Verifier {
	if runner == nil {
		runner = CommandRunner{}
	}
	return Verifier{Runner: runner}
}

func (v Verifier) Verify(ctx context.Context, path, platform, architecture string) error {
	if v.Runner == nil || path == "" || !validArchitecture(architecture) {
		return ErrInvalid
	}
	switch platform {
	case "linux":
		return nil
	case "darwin":
		return v.verifyDarwin(ctx, path)
	case "windows":
		return v.verifyWindows(ctx, path)
	default:
		return ErrInvalid
	}
}

func (v Verifier) verifyDarwin(ctx context.Context, path string) error {
	// codesign validates the embedded signature and designated requirements.
	// spctl performs Gatekeeper assessment, which rejects code that is not
	// accepted for execution, including an unnotarized distribution.
	if _, err := v.Runner.Run(ctx, "codesign", "--verify", "--deep", "--strict", "--verbose=2", path); err != nil {
		return fmt.Errorf("%w: codesign", ErrInvalid)
	}
	if _, err := v.Runner.Run(ctx, "spctl", "--assess", "--type", "execute", "--verbose=4", path); err != nil {
		return fmt.Errorf("%w: gatekeeper assessment", ErrInvalid)
	}
	return nil
}

func (v Verifier) verifyWindows(ctx context.Context, path string) error {
	// The path is encoded as a PowerShell single-quoted literal. Runner still
	// invokes powershell.exe directly, never through cmd.exe. Status must be
	// Valid, which includes Authenticode chain validation by Windows.
	escapedPath := strings.ReplaceAll(path, "'", "''")
	script := "$signature = Get-AuthenticodeSignature -LiteralPath '" + escapedPath + "'; if ($signature.Status -ne 'Valid') { Write-Error ('Authenticode status: ' + $signature.Status); exit 1 }; [Console]::Out.Write($signature.Status)"
	output, err := v.Runner.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil || strings.TrimSpace(string(output)) != "Valid" {
		return fmt.Errorf("%w: authenticode", ErrInvalid)
	}
	return nil
}

func validArchitecture(architecture string) bool {
	return architecture == "amd64" || architecture == "arm64"
}

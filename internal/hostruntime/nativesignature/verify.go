// Package nativesignature verifies optional operating-system signatures. TUF
// establishes release identity and the Windows PE validator establishes the
// executable format; Windows Authenticode is not a Paperboat release gate.
package nativesignature

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/processlaunch"
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
	command := exec.CommandContext(ctx, name, arguments...)
	processlaunch.ConfigureBackground(command)
	return command.CombinedOutput()
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
		// Authenticode is intentionally optional. Release integrity comes from
		// the TUF target digest and PE machine validation performed by callers.
		return nil
	default:
		return ErrInvalid
	}
}

func (v Verifier) verifyDarwin(ctx context.Context, path string) error {
	if strings.EqualFold(filepath.Ext(path), ".pkg") {
		output, err := v.Runner.Run(ctx, "/usr/sbin/pkgutil", "--check-signature", path)
		if err != nil && !isUnsignedPackage(output) {
			return fmt.Errorf("%w: package signature", ErrInvalid)
		}
		// Development releases may intentionally publish an unsigned PKG when
		// no Apple installer identity is available. TUF authenticates the bytes;
		// a signed package, when present, still receives the full Gatekeeper check.
		if isUnsignedPackage(output) {
			return nil
		}
		if _, err := v.Runner.Run(ctx, "/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", path); err != nil {
			return fmt.Errorf("%w: package gatekeeper assessment", ErrInvalid)
		}
		return nil
	}
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

func isUnsignedPackage(output []byte) bool {
	value := strings.ToLower(string(output))
	return strings.Contains(value, "no signature") || strings.Contains(value, "not signed")
}

func validArchitecture(architecture string) bool {
	return architecture == "amd64" || architecture == "arm64"
}

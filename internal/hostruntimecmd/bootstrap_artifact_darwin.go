//go:build darwin

package hostruntimecmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
)

var errDarwinBootstrapPackage = errors.New("invalid macOS Paperboat package")

// materializeUnixBootstrapArtifact is the explicit package boundary for a
// first install. The DMG is validated before it is mounted and its unified
// executable is copied into the requested installation slot.
func materializeUnixBootstrapArtifact(ctx context.Context, packagePath string) (string, error) {
	if packagePath == "" || !filepath.IsAbs(packagePath) || filepath.Clean(packagePath) != packagePath || !strings.EqualFold(filepath.Ext(packagePath), ".dmg") {
		return "", errDarwinBootstrapPackage
	}
	info, err := os.Lstat(packagePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errDarwinBootstrapPackage
	}
	if err := nativesignature.New(nil).Verify(ctx, packagePath, "darwin", "arm64"); err != nil {
		return "", err
	}
	mountpoint, err := os.MkdirTemp("", "paperboat-dmg-mount-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(mountpoint)
	command := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mountpoint, packagePath)
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mount Paperboat DMG: %w: %s", err, strings.TrimSpace(string(output)))
	}
	defer exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", mountpoint, "-quiet").Run()
	executable := "/usr/local/bin/pb"
	if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
		return "", err
	}
	input := filepath.Join(mountpoint, "pb")
	if err := os.Chmod(input, 0755); err != nil {
		return "", err
	}
	if err := os.Rename(input, executable); err != nil {
		data, readErr := os.ReadFile(input)
		if readErr != nil {
			return "", readErr
		}
		if writeErr := os.WriteFile(executable, data, 0755); writeErr != nil {
			return "", writeErr
		}
	}
	if err := binarytarget.Validate(executable, "darwin", "arm64"); err != nil {
		return "", err
	}
	if err := nativesignature.New(nil).Verify(ctx, executable, "darwin", "arm64"); err != nil {
		return "", err
	}
	return executable, nil
}

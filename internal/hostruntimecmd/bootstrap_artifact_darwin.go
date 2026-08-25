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
// first install. A signed PKG is verified before installer(8) is invoked; its
// bytes are never treated as an executable or copied into a pb slot.
func materializeUnixBootstrapArtifact(ctx context.Context, packagePath string) (string, error) {
	if packagePath == "" || !filepath.IsAbs(packagePath) || filepath.Clean(packagePath) != packagePath || !strings.EqualFold(filepath.Ext(packagePath), ".pkg") {
		return "", errDarwinBootstrapPackage
	}
	info, err := os.Lstat(packagePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errDarwinBootstrapPackage
	}
	if err := nativesignature.New(nil).Verify(ctx, packagePath, "darwin", "arm64"); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", "/usr/sbin/installer", "-pkg", packagePath, "-target", "/")
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("install Paperboat package: %w: %s", err, strings.TrimSpace(string(output)))
	}
	executable := "/usr/local/bin/pb"
	if err := binarytarget.Validate(executable, "darwin", "arm64"); err != nil {
		return "", err
	}
	if err := nativesignature.New(nil).Verify(ctx, executable, "darwin", "arm64"); err != nil {
		return "", err
	}
	return executable, nil
}

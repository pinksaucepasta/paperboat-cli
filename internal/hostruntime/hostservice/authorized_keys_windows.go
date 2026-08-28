//go:build windows

package hostservice

import (
	"context"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
)

// WindowsAuthorizedKeys owns the fixed, machine-wide PaperboatSshd
// authorization file. The enrolled owner can supply key material through the
// SID-restricted host-service pipe, but it can never select a filesystem path.
type WindowsAuthorizedKeys struct{ stateRoot string }

func NewWindowsAuthorizedKeys() (*WindowsAuthorizedKeys, error) {
	return newWindowsAuthorizedKeys(filepath.Join(hostinstall.WindowsProgramDataRoot(), "ssh"))
}

func newWindowsAuthorizedKeys(stateRoot string) (*WindowsAuthorizedKeys, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return nil, ErrInvalidConfig
	}
	return &WindowsAuthorizedKeys{stateRoot: stateRoot}, nil
}

func (r *WindowsAuthorizedKeys) ReconcileAuthorizedKeys(ctx context.Context, keys []string) (bool, error) {
	if r == nil || ctx == nil {
		return false, ErrInvalidConfig
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	return windowsopenssh.ReconcileAuthorizedKeysContext(ctx, r.stateRoot, keys)
}

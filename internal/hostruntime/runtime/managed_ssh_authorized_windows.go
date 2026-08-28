//go:build windows

package runtime

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
)

type windowsAuthorizedKeysClient interface {
	ReconcileAuthorizedKeys(context.Context, []string) (bool, error)
}

var newWindowsAuthorizedKeysClient = func(timeout time.Duration) (windowsAuthorizedKeysClient, error) {
	return hostservice.NewClient(hostservice.DefaultSocketPath(), timeout)
}

func reconcilePlatformAuthorizedKeys(stateRoot string, _ uint32, keys []string) (bool, error) {
	expectedRoot := filepath.Join(hostinstall.WindowsProgramDataRoot(), "ssh")
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || !strings.EqualFold(stateRoot, expectedRoot) {
		return false, ErrProductionInvalid
	}
	const timeout = 5 * time.Second
	client, err := newWindowsAuthorizedKeysClient(timeout)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return client.ReconcileAuthorizedKeys(ctx, keys)
}

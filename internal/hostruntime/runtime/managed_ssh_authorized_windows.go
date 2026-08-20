//go:build windows

package runtime

import "github.com/pinksaucepasta/paperboat/internal/windowsopenssh"

func reconcilePlatformAuthorizedKeys(stateRoot string, _ uint32, keys []string) (bool, error) {
	return windowsopenssh.ReconcileAuthorizedKeys(stateRoot, keys)
}

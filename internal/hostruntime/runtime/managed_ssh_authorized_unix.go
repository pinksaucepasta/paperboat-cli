//go:build darwin || linux

package runtime

import "github.com/pinksaucepasta/paperboat/internal/managedssh"

func reconcilePlatformAuthorizedKeys(home string, ownerUID uint32, keys []string) (bool, error) {
	result, err := managedssh.ReconcileAuthorizedKeys(home, ownerUID, keys)
	return result.Changed, err
}

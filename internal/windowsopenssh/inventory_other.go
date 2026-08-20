//go:build !windows

package windowsopenssh

import "context"

func collectInventory(context.Context, Config) (InventoryRecord, error) {
	return InventoryRecord{}, ErrInstallerUnavailable
}

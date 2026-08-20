package windowsopenssh

import (
	"context"
	"errors"
)

type RepairResult struct {
	SetupResult
	Inventory InstallationInventory
	Health    ServiceHealth
}

// Repair restores Paperboat-owned OpenSSH state only. The normal sshd service,
// its keys, its config, and its firewall rules are inspected but never changed.
func Repair(ctx context.Context, config Config) (RepairResult, error) {
	inventory, err := Inventory(ctx, config)
	if err != nil {
		return RepairResult{}, errors.Join(ErrRepairFailed, err)
	}
	if inventory.Class == InstallationConflicting {
		return RepairResult{Inventory: inventory}, errors.Join(ErrRepairFailed, ErrConflictingInstall)
	}
	var result Result
	if inventory.Class == InstallationPaperboatApproved {
		result, err = verifyInstalledResult(ctx, config)
	} else {
		result, err = provision(ctx, config, true)
	}
	if err != nil {
		return RepairResult{Inventory: inventory}, errors.Join(ErrRepairFailed, err)
	}
	setup, err := setupFromResult(ctx, config, result)
	if err != nil {
		return RepairResult{Inventory: inventory}, errors.Join(ErrRepairFailed, err)
	}
	health, err := CheckLoopbackHealth(ctx, config, setup.Result)
	if err != nil {
		return RepairResult{SetupResult: setup, Inventory: inventory}, errors.Join(ErrRepairFailed, err)
	}
	if err := RepairFirewallOwnership(ctx, config); err != nil {
		return RepairResult{SetupResult: setup, Inventory: inventory, Health: health}, err
	}
	return RepairResult{SetupResult: setup, Inventory: inventory, Health: health}, nil
}

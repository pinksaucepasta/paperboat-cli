package localdaemon

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

func managedSSHAliasTargets(ctx context.Context, client *api.Client) ([]managedssh.OpenSSHAliasTarget, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	machines, err := client.ListUserMachines(lookupCtx)
	if err != nil {
		return nil, err
	}
	targets := make([]managedssh.OpenSSHAliasTarget, 0, len(machines))
	var mu sync.Mutex
	var resultErr error
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, machine := range machines {
		if machine.State == "revoked" || machine.State == "deleted" || machine.InstallationGeneration < 1 {
			continue
		}
		wg.Add(1)
		go func(machine api.UserMachine) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-lookupCtx.Done():
				return
			}
			target, targetErr := client.ManagedSSHTarget(lookupCtx, machine.ID, uint64(machine.InstallationGeneration))
			mu.Lock()
			defer mu.Unlock()
			if targetErr == nil {
				targets = append(targets, managedssh.OpenSSHAliasTarget{Alias: machine.Alias, DisplayName: machine.DisplayName, User: target.OSUser, Port: target.Port})
			} else if !api.IsNotFound(targetErr) {
				resultErr = errors.Join(resultErr, targetErr)
			}
		}(machine)
	}
	wg.Wait()
	if resultErr != nil || lookupCtx.Err() != nil {
		return nil, errors.Join(resultErr, lookupCtx.Err())
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Alias < targets[j].Alias })
	return targets, nil
}

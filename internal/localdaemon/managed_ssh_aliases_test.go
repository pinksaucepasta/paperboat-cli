package localdaemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

func TestManagedSSHAliasTargetsReconcilesChangedAndRemovedMachines(t *testing.T) {
	type targetState struct {
		mu       sync.RWMutex
		machines []api.UserMachine
		targets  map[string]api.ManagedSSHTarget
	}
	state := &targetState{
		machines: []api.UserMachine{{
			ID: "machine_1", Alias: "victus", DisplayName: "Victus", State: "active", InstallationGeneration: 1,
		}},
		targets: map[string]api.ManagedSSHTarget{
			"machine_1": {Type: "machine_target", Version: 1, MachineID: "machine_1", MachineGeneration: 1, OSUser: "Pujan", Port: 38222, ReconciliationVersion: 1},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/v1/machines":
			writeManagedSSHTestResponse(writer, api.UserMachinePage{Items: append([]api.UserMachine(nil), state.machines...), Pagination: api.Pagination{}})
		case strings.HasPrefix(request.URL.Path, "/v1/machines/") && strings.HasSuffix(request.URL.Path, "/ssh-target"):
			machineID, err := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/machines/"), "/ssh-target"))
			if err != nil {
				http.Error(writer, "invalid machine", http.StatusBadRequest)
				return
			}
			target, ok := state.targets[machineID]
			if !ok {
				http.NotFound(writer, request)
				return
			}
			writeManagedSSHTestResponse(writer, target)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := api.New(server.URL, config.Credential{AccessToken: "test-token"}, server.Client())

	got, err := managedSSHAliasTargets(context.Background(), client)
	if err != nil {
		t.Fatalf("initial target reconciliation: %v", err)
	}
	assertManagedSSHAliasTarget(t, got, managedSSHExpectedAliasTarget{alias: "victus", displayName: "Victus", user: "Pujan", port: 38222})

	state.mu.Lock()
	state.machines[0].InstallationGeneration = 2
	state.targets["machine_1"] = api.ManagedSSHTarget{
		Type: "machine_target", Version: 1, MachineID: "machine_1", MachineGeneration: 2, OSUser: "Administrator", Port: 38223, ReconciliationVersion: 2,
	}
	state.mu.Unlock()
	got, err = managedSSHAliasTargets(context.Background(), client)
	if err != nil {
		t.Fatalf("changed target reconciliation: %v", err)
	}
	assertManagedSSHAliasTarget(t, got, managedSSHExpectedAliasTarget{alias: "victus", displayName: "Victus", user: "Administrator", port: 38223})

	state.mu.Lock()
	state.machines = nil
	state.mu.Unlock()
	got, err = managedSSHAliasTargets(context.Background(), client)
	if err != nil {
		t.Fatalf("removed target reconciliation: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("removed machine remained in aliases: %+v", got)
	}
}

type managedSSHExpectedAliasTarget struct {
	alias, displayName, user string
	port                     uint16
}

func assertManagedSSHAliasTarget(t *testing.T, got []managedssh.OpenSSHAliasTarget, want managedSSHExpectedAliasTarget) {
	t.Helper()
	if len(got) != 1 || got[0].Alias != want.alias || got[0].DisplayName != want.displayName || got[0].User != want.user || got[0].Port != want.port {
		t.Fatalf("aliases=%+v, want one target %+v", got, want)
	}
}

func writeManagedSSHTestResponse(writer http.ResponseWriter, value any) {
	_ = json.NewEncoder(writer).Encode(map[string]any{"data": value})
}

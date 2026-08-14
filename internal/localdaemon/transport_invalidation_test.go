package localdaemon

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

type recordingTransportInvalidator struct{ prefixes, retired []string }

func (r *recordingTransportInvalidator) InvalidatePrefix(prefix string) error {
	r.prefixes = append(r.prefixes, prefix)
	return nil
}
func (r *recordingTransportInvalidator) RetirePrefix(prefix string) error {
	r.retired = append(r.retired, prefix)
	return nil
}

func TestMachineTransportInvalidatorFencesAuthorityTransitions(t *testing.T) {
	base := api.UserMachine{
		ID: "machine_1", EnvironmentID: "environment_1", State: "online", Online: true,
		PublicIdentityKey: "identity_1", InstallationGeneration: 3,
		RuntimeDiagnostics: api.RuntimeDiagnostics{ConnectorGeneration: 5, WorkerGeneration: 7, OSBootID: "boot_1", WorkerServiceScope: "system"},
		Availability:       api.AvailabilityPolicy{DesiredMode: "keep_awake", DesiredVersion: 2, ObservedMode: "keep_awake", ObservedVersion: 2, Status: "applied"},
	}
	tests := map[string]func(*api.UserMachine){
		"environment":              func(value *api.UserMachine) { value.EnvironmentID = "environment_2" },
		"terminal lifecycle state": func(value *api.UserMachine) { value.State = "revoked" },
		"identity":                 func(value *api.UserMachine) { value.PublicIdentityKey = "identity_2" },
		"installation":             func(value *api.UserMachine) { value.InstallationGeneration++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := &recordingTransportInvalidator{}
			observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState)}
			if observer.Observe([]api.UserMachine{base}) || len(recorder.prefixes) != 0 {
				t.Fatal("baseline invalidated transports")
			}
			if observer.Observe([]api.UserMachine{base}) || len(recorder.prefixes) != 0 {
				t.Fatal("stable inventory invalidated transports")
			}
			changed := base
			mutate(&changed)
			if !observer.Observe([]api.UserMachine{changed}) || len(recorder.prefixes) != 1 || recorder.prefixes[0] != "machine_1:" {
				t.Fatalf("transition invalidated=%v", recorder.prefixes)
			}
		})
	}
}

func TestMachineTransportInvalidatorRetiresObservedRouteChanges(t *testing.T) {
	base := api.UserMachine{
		ID: "machine_1", EnvironmentID: "environment_1", State: "online", Online: true,
		PublicIdentityKey: "identity_1", InstallationGeneration: 3,
		RuntimeDiagnostics: api.RuntimeDiagnostics{ConnectorGeneration: 5, WorkerGeneration: 7, OSBootID: "boot_1", WorkerServiceScope: "system"},
	}
	tests := map[string]func(*api.UserMachine){
		"liveness":             func(value *api.UserMachine) { value.Online = false },
		"nonterminal state":    func(value *api.UserMachine) { value.State = "offline" },
		"connector generation": func(value *api.UserMachine) { value.RuntimeDiagnostics.ConnectorGeneration++ },
		"worker generation":    func(value *api.UserMachine) { value.RuntimeDiagnostics.WorkerGeneration++ },
		"boot identity":        func(value *api.UserMachine) { value.RuntimeDiagnostics.OSBootID = "boot_2" },
		"worker service scope": func(value *api.UserMachine) { value.RuntimeDiagnostics.WorkerServiceScope = "user" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			recorder := &recordingTransportInvalidator{}
			observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState)}
			observer.Observe([]api.UserMachine{base})
			changed := base
			mutate(&changed)
			if !observer.Observe([]api.UserMachine{changed}) {
				t.Fatal("route change was not observed")
			}
			if len(recorder.prefixes) != 0 || len(recorder.retired) != 1 || recorder.retired[0] != "machine_1:" {
				t.Fatalf("invalidated=%v retired=%v", recorder.prefixes, recorder.retired)
			}
		})
	}
}

func TestMachineTransportInvalidatorFencesInventoryMembership(t *testing.T) {
	recorder := &recordingTransportInvalidator{}
	observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState)}
	first := api.UserMachine{ID: "machine_1"}
	second := api.UserMachine{ID: "machine_2"}
	observer.Observe([]api.UserMachine{first})
	if observer.Observe([]api.UserMachine{first, second}) || len(recorder.prefixes) != 0 {
		t.Fatalf("addition invalidated=%v", recorder.prefixes)
	}
	if !observer.Observe([]api.UserMachine{second}) || len(recorder.prefixes) != 1 || recorder.prefixes[0] != "machine_1:" {
		t.Fatalf("removal invalidated=%v", recorder.prefixes)
	}
}

func TestMachineTransportInvalidatorDoesNotFenceUnchangedMachine(t *testing.T) {
	recorder := &recordingTransportInvalidator{}
	observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState)}
	first := api.UserMachine{ID: "machine_1", Online: true}
	second := api.UserMachine{ID: "machine_2", Online: true}
	observer.Observe([]api.UserMachine{first, second})
	second.Online = false
	if !observer.Observe([]api.UserMachine{first, second}) || len(recorder.prefixes) != 0 || len(recorder.retired) != 1 || recorder.retired[0] != "machine_2:" {
		t.Fatalf("invalidated=%v retired=%v", recorder.prefixes, recorder.retired)
	}
}

func TestMachineTransportInvalidatorRetainsAuthorityAcrossPolicyReconciliation(t *testing.T) {
	recorder := &recordingTransportInvalidator{}
	var authorities []string
	observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState), authority: func(machineID string) { authorities = append(authorities, machineID) }}
	base := api.UserMachine{ID: "machine_1", Online: true, InstallationGeneration: 3, PublicIdentityKey: "identity_1", Availability: api.AvailabilityPolicy{DesiredVersion: 1, ObservedVersion: 1, Status: "pending"}}
	observer.Observe([]api.UserMachine{base})
	changed := base
	changed.Availability.ObservedVersion = 2
	changed.Availability.Status = "applied"
	if observer.Observe([]api.UserMachine{changed}) || len(recorder.prefixes) != 0 || len(recorder.retired) != 0 {
		t.Fatalf("observed policy reconciliation fenced carrier: %v", recorder.prefixes)
	}
	if len(authorities) != 0 {
		t.Fatalf("policy transition invalidated endpoint authority: %v", authorities)
	}
	changed.RuntimeDiagnostics.WorkerGeneration = 4
	if !observer.Observe([]api.UserMachine{changed}) || len(recorder.prefixes) != 0 || len(recorder.retired) != 1 || len(authorities) != 0 {
		t.Fatalf("worker transition invalidated endpoint authority: prefixes=%v authorities=%v", recorder.prefixes, authorities)
	}
}

func TestMachineTransportInvalidatorFencesDesiredPolicyChange(t *testing.T) {
	recorder := &recordingTransportInvalidator{}
	observer := &MachineTransportInvalidator{manager: recorder, seen: make(map[string]machineTransportState)}
	base := api.UserMachine{ID: "machine_1", Availability: api.AvailabilityPolicy{DesiredMode: "keep_awake", DesiredVersion: 3}}
	observer.Observe([]api.UserMachine{base})
	base.Availability.DesiredVersion++
	if !observer.Observe([]api.UserMachine{base}) || len(recorder.prefixes) != 0 || len(recorder.retired) != 1 || recorder.retired[0] != "machine_1:" {
		t.Fatalf("desired policy change invalidated=%v retired=%v", recorder.prefixes, recorder.retired)
	}
}

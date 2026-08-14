package localdaemon

import (
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
)

// MachineTransportInvalidator fences daemon-owned carriers when the control
// plane changes the authority or policy they were built from.
type MachineTransportInvalidator struct {
	manager   transportCacheInvalidator
	mu        sync.Mutex
	seen      map[string]machineTransportState
	ready     bool
	authority func(string)
}

type transportCacheInvalidator interface {
	InvalidatePrefix(string) error
	RetirePrefix(string) error
}

type machineTransportState struct {
	environmentID       string
	state               string
	online              bool
	identityKey         string
	installationGen     int64
	connectorGeneration uint64
	workerGeneration    uint64
	osBootID            string
	serviceScope        string
	desiredMode         string
	desiredVersion      int64
}

func NewMachineTransportInvalidator(manager *transportmanager.Manager) *MachineTransportInvalidator {
	if manager == nil {
		return nil
	}
	return &MachineTransportInvalidator{manager: manager, seen: make(map[string]machineTransportState)}
}

// Observe returns true when at least one machine's transport authority changed.
// The first observation establishes a baseline and never invalidates carriers.
func (o *MachineTransportInvalidator) Observe(machines []api.UserMachine) bool {
	if o == nil || o.manager == nil {
		return false
	}
	o.mu.Lock()
	baseline := !o.ready
	previousSeen := o.seen
	changed := make(map[string]struct{})
	current := make(map[string]machineTransportState, len(machines))
	for _, machine := range machines {
		state := transportState(machine)
		current[machine.ID] = state
		if previous, ok := o.seen[machine.ID]; ok && previous != state {
			changed[machine.ID] = struct{}{}
		}
	}
	for machineID := range o.seen {
		if _, ok := current[machineID]; !ok {
			changed[machineID] = struct{}{}
		}
	}
	o.seen = current
	o.ready = true
	o.mu.Unlock()
	if baseline {
		return false
	}
	for machineID := range changed {
		previous, hadPrevious := previousSeen[machineID]
		currentState, hasCurrent := current[machineID]
		authorityChanged := !hadPrevious || !hasCurrent || authorityStateChanged(previous, currentState)
		if authorityChanged {
			_ = o.manager.InvalidatePrefix(machineID + ":")
		} else {
			_ = o.manager.RetirePrefix(machineID + ":")
		}
		if o.authority != nil && authorityChanged {
			o.authority(machineID)
		}
	}
	return len(changed) > 0
}

// Authority metadata is independently cacheable from active carrier policy.
// Liveness and runtime diagnostics describe an observed route, not the
// authenticated peer identity carried by an established connection.
func authorityStateChanged(previous, current machineTransportState) bool {
	return previous.environmentID != current.environmentID || previous.identityKey != current.identityKey || previous.installationGen != current.installationGen || terminalMachineState(previous.state) != terminalMachineState(current.state)
}

func terminalMachineState(state string) bool {
	return state == "revoked" || state == "deleted"
}

func transportState(machine api.UserMachine) machineTransportState {
	return machineTransportState{
		environmentID:       machine.EnvironmentID,
		state:               machine.State,
		online:              machine.Online,
		identityKey:         machine.PublicIdentityKey,
		installationGen:     machine.InstallationGeneration,
		connectorGeneration: machine.RuntimeDiagnostics.ConnectorGeneration,
		workerGeneration:    machine.RuntimeDiagnostics.WorkerGeneration,
		osBootID:            machine.RuntimeDiagnostics.OSBootID,
		serviceScope:        machine.RuntimeDiagnostics.WorkerServiceScope,
		desiredMode:         machine.Availability.DesiredMode,
		desiredVersion:      machine.Availability.DesiredVersion,
	}
}

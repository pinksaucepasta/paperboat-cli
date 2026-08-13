package connectionmanager

import (
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

var ErrQualityGenerationExhausted = errors.New("quality key local network generation exhausted")

// QualityKeyAuthority is the single generation-fenced source used by direct
// recovery probes and selected-path health recording. It stores only an opaque
// network fingerprint and remote authority generations.
type QualityKeyAuthority struct {
	mu                sync.Mutex
	key               QualityKey
	localNetwork      uint64
	valid             bool
	machineID         string
	minimumHostNet    uint64
	minimumHostProc   uint64
	minimumAuthorized uint64
	exhausted         bool
}

func NewQualityKeyAuthority(key QualityKey, localNetworkGeneration uint64) (*QualityKeyAuthority, error) {
	if !key.valid() || localNetworkGeneration == 0 {
		return nil, errors.New("invalid quality key authority")
	}
	return &QualityKeyAuthority{
		key: key, localNetwork: localNetworkGeneration, valid: true, machineID: key.MachineID,
		minimumHostNet: key.HostNetworkGeneration, minimumHostProc: key.HostProcessGeneration,
		minimumAuthorized: key.AuthorizationGeneration,
	}, nil
}

// Replace publishes a current local-network fingerprint and remote authority
// tuple. Local or remote generation rollback and same-generation fingerprint
// substitution fail closed.
func (a *QualityKeyAuthority) Replace(key QualityKey, localNetworkGeneration uint64) error {
	if a == nil || !key.valid() || localNetworkGeneration == 0 {
		return errors.New("invalid quality key replacement")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exhausted {
		return ErrQualityGenerationExhausted
	}
	if key.MachineID != a.machineID || localNetworkGeneration < a.localNetwork || key.HostNetworkGeneration < a.minimumHostNet || key.HostProcessGeneration < a.minimumHostProc || key.AuthorizationGeneration < a.minimumAuthorized {
		return errors.New("quality key generation rollback")
	}
	if localNetworkGeneration == a.localNetwork && a.valid && key.NetworkFingerprint != a.key.NetworkFingerprint {
		return errors.New("quality key fingerprint changed without a network generation")
	}
	a.key = key
	a.localNetwork = localNetworkGeneration
	a.valid = true
	a.minimumHostNet = key.HostNetworkGeneration
	a.minimumHostProc = key.HostProcessGeneration
	a.minimumAuthorized = key.AuthorizationGeneration
	return nil
}

func (a *QualityKeyAuthority) QualityKey(attempt ProbeAttempt) (QualityKey, error) {
	if attempt.Generation == 0 || attempt.NetworkGeneration == 0 {
		return QualityKey{}, errors.New("invalid quality probe key request")
	}
	return a.resolve(attempt.NetworkGeneration)
}

func (a *QualityKeyAuthority) ActiveHealthQualityKey(binding ActiveHealthBinding) (QualityKey, error) {
	if !validActiveHealthBinding(binding) {
		return QualityKey{}, errors.New("invalid active health key request")
	}
	return a.resolve(binding.NetworkGeneration)
}

func (a *QualityKeyAuthority) resolve(localNetworkGeneration uint64) (QualityKey, error) {
	if a == nil {
		return QualityKey{}, errors.New("quality key authority unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.valid || localNetworkGeneration != a.localNetwork {
		return QualityKey{}, errors.New("quality key is stale for the local network generation")
	}
	return a.key, nil
}

// Invalidate removes the fingerprint-bearing tuple while retaining generation
// floors that prevent a later descriptor rollback.
func (a *QualityKeyAuthority) Invalidate() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.localNetwork == ^uint64(0) {
		a.exhausted = true
		return a.invalidateLocked()
	}
	a.localNetwork++
	return a.invalidateLocked()
}

// InvalidateNetwork fences the exact monitor generation before clearing the
// fingerprint-bearing tuple. Older or duplicate events cannot retire a newer
// authority state.
func (a *QualityKeyAuthority) InvalidateNetwork(localNetworkGeneration uint64) int {
	if a == nil || localNetworkGeneration == 0 {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exhausted {
		return 0
	}
	if localNetworkGeneration <= a.localNetwork {
		return 0
	}
	a.localNetwork = localNetworkGeneration
	return a.invalidateLocked()
}

// ApplyNetworkEvent consumes only the monitor's opaque fingerprint. A valid
// rebind publishes the new local-network tuple using the retained remote
// generation floors; an event without a fingerprint leaves recording fenced.
func (a *QualityKeyAuthority) ApplyNetworkEvent(event networkmonitor.Event) int {
	if a == nil || event.Generation == 0 || !event.Rebind {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exhausted {
		return 0
	}
	if event.Generation <= a.localNetwork {
		return 0
	}
	previous := a.invalidateLocked()
	a.localNetwork = event.Generation
	if !event.FingerprintValid || event.Fingerprint == [32]byte{} {
		return previous
	}
	a.key = QualityKey{
		NetworkFingerprint: event.Fingerprint, MachineID: a.machineID,
		HostNetworkGeneration: a.minimumHostNet, HostProcessGeneration: a.minimumHostProc,
		AuthorizationGeneration: a.minimumAuthorized,
	}
	a.valid = true
	return previous
}

func (a *QualityKeyAuthority) invalidateLocked() int {
	if !a.valid {
		return 0
	}
	a.key = QualityKey{}
	a.valid = false
	return 1
}

var _ QualityKeySource = (*QualityKeyAuthority)(nil)
var _ ActiveHealthQualityKeySource = (*QualityKeyAuthority)(nil)

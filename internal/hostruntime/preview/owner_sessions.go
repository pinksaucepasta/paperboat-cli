package preview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	ErrOwnerSessionRegistryInvalid = errors.New("invalid preview owner-session registry")
	ErrOwnerSessionRegistryClosed  = errors.New("preview owner-session registry is closed")
	ErrOwnerSessionBinding         = errors.New("preview owner-session binding is invalid")
	ErrOwnerSessionLimit           = errors.New("preview owner-session limit reached")
)

const defaultRuntimeOwnerSessionLimit = 1024

const localOwnerSessionPrefix = "owner_local_"

// RuntimeOwnerSessionRegistry binds dashboard-dispatched owner_session_id
// values to the authenticated host runtime lifetime. A browser request is
// never used as the lifetime source: the selected device keeps owning the
// lease until its control/runtime session ends or this registry shuts down.
type RuntimeOwnerSessionRegistry struct {
	accountID   string
	machineID   string
	runtimeDone <-chan struct{}
	max         int

	mu       sync.Mutex
	closed   bool
	sessions map[runtimeOwnerSessionKey]*runtimeOwnerSession
	// unbound holds owner sessions minted by the local hostd lease endpoint
	// before the control-plane dispatch supplies its account. The first
	// dispatch binds the account permanently for that short-lived entry.
	unbound map[string]*runtimeOwnerSession
}

type RuntimeOwnerSessionRegistryConfig struct {
	AccountID   string
	MachineID   string
	RuntimeDone <-chan struct{}
	MaxSessions int
}

type runtimeOwnerSession struct {
	done         chan struct{}
	refs         int
	closed       bool
	boundAccount string
	target       LeaseTarget
	hasTarget    bool
}

type runtimeOwnerSessionKey struct {
	accountID      string
	ownerSessionID string
}

func NewRuntimeOwnerSessionRegistry(config RuntimeOwnerSessionRegistryConfig) (*RuntimeOwnerSessionRegistry, error) {
	config.AccountID = strings.TrimSpace(config.AccountID)
	config.MachineID = strings.TrimSpace(config.MachineID)
	// Empty AccountID is an explicit machine-wide mode. The account remains
	// part of each key, so two accounts can never share an owner lifetime.
	if config.AccountID != "" && !validLeaseID(config.AccountID) || !validLeaseID(config.MachineID) || config.RuntimeDone == nil {
		return nil, ErrOwnerSessionRegistryInvalid
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = defaultRuntimeOwnerSessionLimit
	}
	if config.MaxSessions < 1 || config.MaxSessions > 65536 {
		return nil, ErrOwnerSessionRegistryInvalid
	}
	registry := &RuntimeOwnerSessionRegistry{
		accountID: config.AccountID, machineID: config.MachineID, runtimeDone: config.RuntimeDone,
		max: config.MaxSessions, sessions: make(map[runtimeOwnerSessionKey]*runtimeOwnerSession), unbound: make(map[string]*runtimeOwnerSession),
	}
	select {
	case <-config.RuntimeDone:
		registry.closed = true
	default:
		go registry.watchRuntime()
	}
	return registry, nil
}

func (r *RuntimeOwnerSessionRegistry) watchRuntime() {
	<-r.runtimeDone
	_ = r.Close()
}

// OwnerSessionDone implements DispatchOwnerSessions. Unknown IDs are
// registered on first dispatch, which is intentional because the dashboard
// creates the opaque owner-session nonce, the server validates/persists/signs
// it, and the authenticated host binds it here. No browser context is
// accepted or retained here.
func (r *RuntimeOwnerSessionRegistry) OwnerSessionDone(accountID, machineID, ownerSessionID string) (<-chan struct{}, error) {
	if r == nil {
		return nil, ErrOwnerSessionRegistryInvalid
	}
	accountID = strings.TrimSpace(accountID)
	machineID = strings.TrimSpace(machineID)
	ownerSessionID = strings.TrimSpace(ownerSessionID)
	if !validLeaseID(accountID) || !validLeaseID(machineID) || !validLeaseID(ownerSessionID) {
		return nil, ErrOwnerSessionBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.accountID != "" && accountID != r.accountID || machineID != r.machineID {
		return nil, fmt.Errorf("%w: account or machine does not match authenticated runtime", ErrOwnerSessionBinding)
	}
	if r.closed {
		return nil, ErrOwnerSessionRegistryClosed
	}
	key := runtimeOwnerSessionKey{accountID: accountID, ownerSessionID: ownerSessionID}
	if existing := r.sessions[key]; existing != nil {
		if existing.closed {
			return nil, fmt.Errorf("%w: owner session is closed", ErrOwnerSessionBinding)
		}
		existing.refs++
		return existing.done, nil
	}
	if existing := r.unbound[ownerSessionID]; existing != nil {
		if existing.closed || existing.boundAccount != "" && existing.boundAccount != accountID {
			return nil, fmt.Errorf("%w: owner session is closed or bound to another account", ErrOwnerSessionBinding)
		}
		existing.boundAccount = accountID
		existing.refs++
		return existing.done, nil
	}
	if strings.HasPrefix(ownerSessionID, localOwnerSessionPrefix) {
		// Hostd-minted IDs are capabilities issued by the local lease manager.
		// An unknown one must never be treated like a dashboard nonce after its
		// retirement record is gone, otherwise a delayed dispatch could revive a
		// process that already released its local lease.
		return nil, fmt.Errorf("%w: local owner session was not acquired", ErrOwnerSessionBinding)
	}
	if len(r.sessions)+len(r.unbound) >= r.max {
		return nil, ErrOwnerSessionLimit
	}
	session := &runtimeOwnerSession{done: make(chan struct{}), refs: 1}
	r.sessions[key] = session
	return session.done, nil
}

// OwnerSessionDoneForTarget is the generation-safe form used by preview
// dispatch. Local hostd owner leases bind both the minted session ID and the
// exact origin target before the server dispatch is accepted.
func (r *RuntimeOwnerSessionRegistry) OwnerSessionDoneForTarget(accountID, machineID, ownerSessionID string, target LeaseTarget) (<-chan struct{}, error) {
	if err := validateLeaseTarget(target); err != nil {
		return nil, fmt.Errorf("%w: target: %v", ErrOwnerSessionBinding, err)
	}
	accountID = strings.TrimSpace(accountID)
	machineID = strings.TrimSpace(machineID)
	ownerSessionID = strings.TrimSpace(ownerSessionID)
	if !validLeaseID(accountID) || !validLeaseID(machineID) || !validLeaseID(ownerSessionID) {
		return nil, ErrOwnerSessionBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.accountID != "" && accountID != r.accountID || machineID != r.machineID {
		return nil, fmt.Errorf("%w: account or machine does not match authenticated runtime", ErrOwnerSessionBinding)
	}
	if r.closed {
		return nil, ErrOwnerSessionRegistryClosed
	}
	key := runtimeOwnerSessionKey{accountID: accountID, ownerSessionID: ownerSessionID}
	if existing := r.sessions[key]; existing != nil {
		if existing.closed || existing.hasTarget && existing.target != target {
			return nil, fmt.Errorf("%w: owner session target differs", ErrOwnerSessionBinding)
		}
		existing.refs++
		return existing.done, nil
	}
	if existing := r.unbound[ownerSessionID]; existing != nil {
		if existing.closed || existing.boundAccount != "" && existing.boundAccount != accountID || existing.hasTarget && existing.target != target {
			return nil, fmt.Errorf("%w: owner session target or account differs", ErrOwnerSessionBinding)
		}
		existing.boundAccount = accountID
		existing.refs++
		return existing.done, nil
	}
	if strings.HasPrefix(ownerSessionID, localOwnerSessionPrefix) {
		return nil, fmt.Errorf("%w: local owner session was not acquired", ErrOwnerSessionBinding)
	}
	if len(r.sessions)+len(r.unbound) >= r.max {
		return nil, ErrOwnerSessionLimit
	}
	session := &runtimeOwnerSession{done: make(chan struct{}), refs: 1, target: target, hasTarget: true, boundAccount: accountID}
	r.sessions[key] = session
	return session.done, nil
}

// RegisterMachineOwnerSession creates the local hostd-owned reference used by
// a CLI foreground process. An empty owner ID asks hostd to mint one; the
// returned ID is carried by the local lease manager, never sent as a secret.
func (r *RuntimeOwnerSessionRegistry) RegisterMachineOwnerSession(machineID, ownerSessionID string, target LeaseTarget) (<-chan struct{}, string, error) {
	if r == nil {
		return nil, "", ErrOwnerSessionRegistryInvalid
	}
	if err := validateLeaseTarget(target); err != nil {
		return nil, "", fmt.Errorf("%w: target: %v", ErrOwnerSessionBinding, err)
	}
	machineID = strings.TrimSpace(machineID)
	ownerSessionID = strings.TrimSpace(ownerSessionID)
	if !validLeaseID(machineID) || ownerSessionID != "" && !validLeaseID(ownerSessionID) {
		return nil, "", ErrOwnerSessionBinding
	}
	if ownerSessionID == "" {
		id, err := newOwnerSessionID()
		if err != nil {
			return nil, "", err
		}
		ownerSessionID = id
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if machineID != r.machineID {
		return nil, "", fmt.Errorf("%w: machine does not match authenticated runtime", ErrOwnerSessionBinding)
	}
	if r.closed {
		return nil, "", ErrOwnerSessionRegistryClosed
	}
	if existing := r.unbound[ownerSessionID]; existing != nil {
		if existing.closed || existing.target != target {
			return nil, "", fmt.Errorf("%w: owner session already exists", ErrOwnerSessionBinding)
		}
		existing.refs++
		return existing.done, ownerSessionID, nil
	}
	if len(r.sessions)+len(r.unbound) >= r.max {
		return nil, "", ErrOwnerSessionLimit
	}
	session := &runtimeOwnerSession{done: make(chan struct{}), refs: 1, target: target, hasTarget: true}
	r.unbound[ownerSessionID] = session
	return session.done, ownerSessionID, nil
}

// CloseMachineOwnerSession signals process loss immediately while retaining a
// bounded registry reference until the local lease manager releases it. This
// fences a delayed server dispatch without creating permanent tombstones.
func (r *RuntimeOwnerSessionRegistry) CloseMachineOwnerSession(machineID, ownerSessionID string) error {
	if r == nil {
		return ErrOwnerSessionRegistryInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if machineID != r.machineID || !validLeaseID(ownerSessionID) {
		return ErrOwnerSessionBinding
	}
	session := r.unbound[ownerSessionID]
	if session == nil {
		return nil
	}
	if !session.closed {
		session.closed = true
		close(session.done)
	}
	return nil
}

// ReleaseMachineOwnerSession releases the local lease's registry reference.
// It is intentionally separate from CloseMachineOwnerSession so an expired
// local lease can fence a delayed dispatch until its bounded lifetime ends.
func (r *RuntimeOwnerSessionRegistry) ReleaseMachineOwnerSession(machineID, ownerSessionID string) error {
	if r == nil {
		return ErrOwnerSessionRegistryInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if machineID != r.machineID || !validLeaseID(ownerSessionID) {
		return ErrOwnerSessionBinding
	}
	key := ownerSessionID
	session := r.unbound[key]
	if session == nil {
		return nil
	}
	if session.refs > 0 {
		session.refs--
	}
	if session.refs == 0 {
		delete(r.unbound, key)
	}
	return nil
}

func newOwnerSessionID() (string, error) {
	value, err := newSessionIdempotencyKey(nil)
	if err != nil {
		return "", err
	}
	return localOwnerSessionPrefix + strings.TrimPrefix(value, "preview_"), nil
}

// Register is an explicit spelling for composition code that wants to bind a
// dispatch owner before sending a request. It has exactly the same account,
// machine, limit, and shutdown guarantees as OwnerSessionDone.
func (r *RuntimeOwnerSessionRegistry) Register(accountID, machineID, ownerSessionID string) (<-chan struct{}, error) {
	return r.OwnerSessionDone(accountID, machineID, ownerSessionID)
}

// ReleaseOwnerSession drops one foreground preview's reference to an owner
// session. The shared channel stays open while another preview uses the same
// owner session. Its final release closes and removes the entry so the
// bounded registry can accept a later signed operation.
func (r *RuntimeOwnerSessionRegistry) ReleaseOwnerSession(accountID, machineID, ownerSessionID string) error {
	if r == nil {
		return ErrOwnerSessionRegistryInvalid
	}
	accountID = strings.TrimSpace(accountID)
	machineID = strings.TrimSpace(machineID)
	ownerSessionID = strings.TrimSpace(ownerSessionID)
	if !validLeaseID(accountID) || !validLeaseID(machineID) || !validLeaseID(ownerSessionID) {
		return ErrOwnerSessionBinding
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.accountID != "" && accountID != r.accountID || machineID != r.machineID {
		return fmt.Errorf("%w: account or machine does not match authenticated runtime", ErrOwnerSessionBinding)
	}
	session := r.sessions[runtimeOwnerSessionKey{accountID: accountID, ownerSessionID: ownerSessionID}]
	if session == nil {
		session = r.unbound[ownerSessionID]
		if session != nil && session.boundAccount != "" && session.boundAccount != accountID {
			return fmt.Errorf("%w: account does not match owner session", ErrOwnerSessionBinding)
		}
	}
	if session == nil {
		return fmt.Errorf("%w: owner session is not active", ErrOwnerSessionBinding)
	}
	if session.refs > 1 {
		session.refs--
		return nil
	}
	key := runtimeOwnerSessionKey{accountID: accountID, ownerSessionID: ownerSessionID}
	if r.sessions[key] == session {
		delete(r.sessions, key)
	} else if r.unbound[ownerSessionID] == session {
		delete(r.unbound, ownerSessionID)
	}
	if !session.closed {
		session.closed = true
		close(session.done)
	}
	return nil
}

// Close terminates all registered owner lifetimes. The registry itself stays
// closed, while a fresh runtime may construct a new registry for later
// dispatches.
func (r *RuntimeOwnerSessionRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	for _, session := range r.sessions {
		if !session.closed {
			session.closed = true
			close(session.done)
		}
	}
	for _, session := range r.unbound {
		if !session.closed {
			session.closed = true
			close(session.done)
		}
	}
	r.mu.Unlock()
	return nil
}

// Shutdown provides the host-runtime lifecycle spelling. Owner channels are
// closed synchronously; ctx is only used to reject an invalid call and is
// never installed as a browser/request lifetime.
func (r *RuntimeOwnerSessionRegistry) Shutdown(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrOwnerSessionRegistryInvalid
	}
	if err := r.Close(); err != nil {
		return err
	}
	return nil
}

var _ DispatchOwnerSessions = (*RuntimeOwnerSessionRegistry)(nil)

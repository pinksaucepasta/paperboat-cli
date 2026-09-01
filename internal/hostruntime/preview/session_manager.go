package preview

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrSessionConflict       = errors.New("preview session already tracked")
	ErrSessionUnknown        = errors.New("preview session not tracked")
	ErrSessionManagerStopped = errors.New("preview session manager stopped")
)

// SessionKey is the local identity used to fence stale renewals and cleanup.
// Generation comes from the canonical strong ETag, so an old session view
// cannot accidentally revoke a newer generation.
type SessionKey struct {
	LeaseID        string
	OwnerSessionID string
	Generation     int64
}

type sessionOwnerKey struct {
	LeaseID        string
	OwnerSessionID string
}

// SessionManager tracks only live foreground sessions. It intentionally has
// no state path, recovery scan, or serialization hook: reboot restoration is
// not valid for preview leases.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[SessionKey]*Session
	owners   map[sessionOwnerKey]*Session
	closed   bool
}

func NewSessionManager() *SessionManager {
	return &SessionManager{sessions: make(map[SessionKey]*Session), owners: make(map[sessionOwnerKey]*Session)}
}

// Track registers an already-created session. Keeping creation separate makes
// retries safe: the manager never creates a second lease merely to discover a
// duplicate local key.
func (m *SessionManager) Track(session *Session) error {
	if m == nil || session == nil {
		return ErrSessionInvalid
	}
	key := session.Key()
	if key.LeaseID == "" || key.OwnerSessionID == "" || key.Generation < 1 {
		return ErrSessionInvalid
	}
	ownerKey := sessionOwnerKey{LeaseID: key.LeaseID, OwnerSessionID: key.OwnerSessionID}
	m.mu.Lock()
	if m.sessions == nil {
		m.sessions = make(map[SessionKey]*Session)
	}
	if m.owners == nil {
		m.owners = make(map[sessionOwnerKey]*Session)
	}
	if m.closed {
		m.mu.Unlock()
		return ErrSessionManagerStopped
	}
	if _, exists := m.sessions[key]; exists {
		m.mu.Unlock()
		return ErrSessionConflict
	}
	if existing := m.owners[ownerKey]; existing != nil {
		m.mu.Unlock()
		return ErrSessionConflict
	}
	m.sessions[key] = session
	m.owners[ownerKey] = session
	m.mu.Unlock()
	session.attachManager(m)
	if err := m.rekey(session, session.currentLease()); err != nil {
		m.untrack(session)
		return err
	}
	go func() {
		<-session.done
		m.untrack(session)
	}()
	return nil
}

func (m *SessionManager) untrack(session *Session) {
	m.mu.Lock()
	for key, current := range m.sessions {
		if current == session {
			delete(m.sessions, key)
		}
	}
	for key, current := range m.owners {
		if current == session {
			delete(m.owners, key)
		}
	}
	m.mu.Unlock()
	session.detachManager(m)
}

func (m *SessionManager) rekey(session *Session, lease Lease) error {
	if m == nil || session == nil {
		return ErrSessionInvalid
	}
	newKey := SessionKey{LeaseID: lease.ID, OwnerSessionID: lease.OwnerSessionID, Generation: lease.Generation}
	if newKey.LeaseID == "" || newKey.OwnerSessionID == "" || newKey.Generation < 1 {
		return ErrSessionInvalid
	}
	ownerKey := sessionOwnerKey{LeaseID: newKey.LeaseID, OwnerSessionID: newKey.OwnerSessionID}
	m.mu.Lock()
	defer m.mu.Unlock()
	var oldKey SessionKey
	found := false
	for key, current := range m.sessions {
		if current == session {
			oldKey, found = key, true
			break
		}
	}
	if !found || m.closed {
		if m.closed {
			return ErrSessionManagerStopped
		}
		return ErrSessionUnknown
	}
	if existing := m.sessions[newKey]; existing != nil && existing != session {
		return ErrSessionConflict
	}
	if existing := m.owners[ownerKey]; existing != nil && existing != session {
		return ErrSessionConflict
	}
	if oldKey != newKey {
		delete(m.sessions, oldKey)
		m.sessions[newKey] = session
	}
	oldOwner := sessionOwnerKey{LeaseID: oldKey.LeaseID, OwnerSessionID: oldKey.OwnerSessionID}
	if oldOwner != ownerKey {
		if existing := m.owners[oldOwner]; existing == session {
			delete(m.owners, oldOwner)
		}
		m.owners[ownerKey] = session
	}
	return nil
}

func (m *SessionManager) Get(key SessionKey) (*Session, error) {
	if m == nil {
		return nil, ErrSessionUnknown
	}
	m.mu.RLock()
	session := m.sessions[key]
	m.mu.RUnlock()
	if session == nil {
		return nil, ErrSessionUnknown
	}
	return session, nil
}

// Revoke performs generation-fenced cleanup for one tracked session.
func (m *SessionManager) Revoke(ctx context.Context, key SessionKey) error {
	session, err := m.Get(key)
	if err != nil {
		return err
	}
	stopErr := session.Stop(ctx)
	m.untrack(session)
	return stopErr
}

func (m *SessionManager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Shutdown stops all tracked sessions and prevents new registration. It does
// not persist or restore any preview state.
func (m *SessionManager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[SessionKey]*Session)
	m.owners = make(map[sessionOwnerKey]*Session)
	m.mu.Unlock()

	results := make(chan error, len(sessions))
	for _, session := range sessions {
		go func(session *Session) {
			results <- session.Stop(ctx)
		}(session)
	}
	var result error
	for range sessions {
		result = errors.Join(result, <-results)
	}
	for _, session := range sessions {
		session.detachManager(m)
	}
	return result
}

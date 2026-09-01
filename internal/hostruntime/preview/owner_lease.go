package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	OwnerSessionLeaseSchema     = "paperboat.preview-owner-session/v1"
	defaultOwnerSessionLeaseTTL = 15 * time.Second
	maxOwnerSessionLeaseTTL     = 5 * time.Minute
	defaultOwnerSessionLeaseMax = 1024
	ownerSessionLeaseBodyLimit  = 16 << 10
)

var (
	ErrOwnerSessionLeaseInvalid      = errors.New("invalid preview owner-session lease")
	ErrOwnerSessionLeaseUnauthorized = errors.New("preview owner-session lease authorization failed")
	ErrOwnerSessionLeaseConflict     = errors.New("preview owner-session lease conflicts with an existing request")
	ErrOwnerSessionLeaseLost         = errors.New("preview owner-session lease is no longer active")
	ErrOwnerSessionLeaseLimit        = errors.New("preview owner-session lease limit reached")
)

// OwnerSessionLease is the local-only capability returned to a foreground
// CLI. Token is never sent to paperboat-server or included in a preview
// dispatch. The manager keeps it in memory and compares it in constant time.
type OwnerSessionLease struct {
	Schema         string      `json:"schema"`
	ID             string      `json:"id"`
	MachineID      string      `json:"machine_id"`
	OwnerSessionID string      `json:"owner_session_id"`
	Target         LeaseTarget `json:"target"`
	ExpiresAt      time.Time   `json:"expires_at"`
	Token          string      `json:"token"`
	// idempotencyKey is local transport metadata used for replay after an
	// uncertain POST. It is not part of the wire response.
	idempotencyKey string
}

type OwnerSessionLeaseManagerConfig struct {
	MachineID    string
	ControlToken string
	Registry     *RuntimeOwnerSessionRegistry
	RunContext   context.Context
	TTL          time.Duration
	MaxLeases    int
	Now          func() time.Time
	Random       io.Reader
}

// OwnerSessionLeaseManager owns local process-lifetime leases. It is separate
// from RuntimeOwnerSessionRegistry so the local control token and lease token
// never enter the server-facing dispatch path.
type OwnerSessionLeaseManager struct {
	machineID    string
	controlToken string
	registry     *RuntimeOwnerSessionRegistry
	ttl          time.Duration
	max          int
	now          func() time.Time
	random       io.Reader
	done         <-chan struct{}

	mu          sync.Mutex
	closed      bool
	leases      map[string]*ownerSessionLeaseEntry
	idempotency map[string]ownerSessionLeaseReplay
}

type ownerSessionLeaseEntry struct {
	lease    OwnerSessionLease
	closed   bool
	retireAt time.Time
}

type ownerSessionLeaseReplay struct {
	hash    string
	leaseID string
}

func NewOwnerSessionLeaseManager(config OwnerSessionLeaseManagerConfig) (*OwnerSessionLeaseManager, error) {
	config.MachineID = strings.TrimSpace(config.MachineID)
	config.ControlToken = strings.TrimSpace(config.ControlToken)
	if !validLeaseID(config.MachineID) || config.ControlToken == "" || config.Registry == nil {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	if config.TTL == 0 {
		config.TTL = defaultOwnerSessionLeaseTTL
	}
	if config.TTL <= 0 || config.TTL > maxOwnerSessionLeaseTTL {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	if config.MaxLeases == 0 {
		config.MaxLeases = defaultOwnerSessionLeaseMax
	}
	if config.MaxLeases < 1 || config.MaxLeases > 65536 {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	manager := &OwnerSessionLeaseManager{
		machineID: config.MachineID, controlToken: config.ControlToken, registry: config.Registry,
		ttl: config.TTL, max: config.MaxLeases, now: config.Now, random: config.Random,
		done: func() <-chan struct{} {
			if config.RunContext == nil {
				return nil
			}
			return config.RunContext.Done()
		}(), leases: make(map[string]*ownerSessionLeaseEntry), idempotency: make(map[string]ownerSessionLeaseReplay),
	}
	if config.RunContext != nil {
		go manager.watchContext()
	}
	return manager, nil
}

func (m *OwnerSessionLeaseManager) watchContext() {
	interval := m.ttl / 3
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			_ = m.Close()
			return
		case now := <-ticker.C:
			m.Sweep(now)
		}
	}
}

// Acquire creates or replays a bounded local owner-session lease. The
// requested owner ID may be empty; in that case hostd mints it.
func (m *OwnerSessionLeaseManager) Acquire(request OwnerSessionLeaseRequest, idempotencyKey string) (OwnerSessionLease, error) {
	if m == nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !validLocalTrace(idempotencyKey) || request.OwnerSessionID != "" && !validLeaseID(request.OwnerSessionID) {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	if err := validateLeaseTarget(request.Target); err != nil {
		return OwnerSessionLease{}, errors.Join(ErrOwnerSessionLeaseInvalid, err)
	}
	hash, err := ownerSessionLeaseRequestHash(request)
	if err != nil {
		return OwnerSessionLease{}, err
	}
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(now)
	if m.closed {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseLost
	}
	if replay, ok := m.idempotency[idempotencyKey]; ok {
		if replay.hash != hash {
			return OwnerSessionLease{}, ErrOwnerSessionLeaseConflict
		}
		entry := m.leases[replay.leaseID]
		if entry == nil || entry.closed {
			return OwnerSessionLease{}, ErrOwnerSessionLeaseLost
		}
		return entry.lease, nil
	}
	activeLeases := 0
	for _, entry := range m.leases {
		if !entry.closed {
			activeLeases++
		}
	}
	if activeLeases >= m.max {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseLimit
	}
	ownerSessionID := request.OwnerSessionID
	if ownerSessionID == "" {
		ownerSessionID, err = newOwnerSessionID()
		if err != nil {
			return OwnerSessionLease{}, err
		}
	}
	if _, existing := m.findOwnerSessionLocked(ownerSessionID); existing {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseConflict
	}
	_, _, err = m.registry.RegisterMachineOwnerSession(m.machineID, ownerSessionID, request.Target)
	if err != nil {
		if errors.Is(err, ErrOwnerSessionLimit) {
			return OwnerSessionLease{}, ErrOwnerSessionLeaseLimit
		}
		return OwnerSessionLease{}, err
	}
	leaseID, err := m.randomID("osl_")
	if err != nil {
		_ = m.registry.CloseMachineOwnerSession(m.machineID, ownerSessionID)
		_ = m.registry.ReleaseMachineOwnerSession(m.machineID, ownerSessionID)
		return OwnerSessionLease{}, err
	}
	token, err := m.randomToken()
	if err != nil {
		_ = m.registry.CloseMachineOwnerSession(m.machineID, ownerSessionID)
		_ = m.registry.ReleaseMachineOwnerSession(m.machineID, ownerSessionID)
		return OwnerSessionLease{}, err
	}
	lease := OwnerSessionLease{Schema: OwnerSessionLeaseSchema, ID: leaseID, MachineID: m.machineID, OwnerSessionID: ownerSessionID, Target: request.Target, ExpiresAt: now.Add(m.ttl), Token: token, idempotencyKey: idempotencyKey}
	m.leases[leaseID] = &ownerSessionLeaseEntry{lease: lease}
	m.idempotency[idempotencyKey] = ownerSessionLeaseReplay{hash: hash, leaseID: leaseID}
	return lease, nil
}

// Heartbeat extends a live lease. A closed or expired lease cannot be revived.
func (m *OwnerSessionLeaseManager) Heartbeat(leaseID, token string) (OwnerSessionLease, error) {
	if m == nil || !validLeaseID(strings.TrimSpace(leaseID)) || strings.TrimSpace(token) == "" {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(now)
	entry := m.leases[leaseID]
	if entry == nil || !secureTokenEqual(entry.lease.Token, token) {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseUnauthorized
	}
	if entry.closed {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseLost
	}
	if !entry.lease.ExpiresAt.After(now) {
		m.closeEntryLocked(entry, now)
		return OwnerSessionLease{}, ErrOwnerSessionLeaseLost
	}
	entry.lease.ExpiresAt = now.Add(m.ttl)
	return entry.lease, nil
}

// Release closes the owner channel immediately. The bounded retirement period
// fences a delayed dispatch that races with process shutdown; Sweep later
// drops the registry reference and replay record.
func (m *OwnerSessionLeaseManager) Release(leaseID, token string) error {
	if m == nil || !validLeaseID(strings.TrimSpace(leaseID)) || strings.TrimSpace(token) == "" {
		return ErrOwnerSessionLeaseInvalid
	}
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked(now)
	entry := m.leases[leaseID]
	if entry == nil {
		return nil
	}
	if !secureTokenEqual(entry.lease.Token, token) {
		return ErrOwnerSessionLeaseUnauthorized
	}
	m.closeEntryLocked(entry, now)
	return nil
}

// Sweep is exported for deterministic tests and is also called by the
// manager's bounded background ticker in production.
func (m *OwnerSessionLeaseManager) Sweep(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sweepLocked(now.UTC())
	m.mu.Unlock()
}

func (m *OwnerSessionLeaseManager) sweepLocked(now time.Time) {
	for leaseID, entry := range m.leases {
		if !entry.closed && !entry.lease.ExpiresAt.After(now) {
			m.closeEntryLocked(entry, now)
		}
		if entry.closed && !entry.retireAt.After(now) {
			_ = m.registry.ReleaseMachineOwnerSession(m.machineID, entry.lease.OwnerSessionID)
			delete(m.leases, leaseID)
			for key, replay := range m.idempotency {
				if replay.leaseID == leaseID {
					delete(m.idempotency, key)
				}
			}
		}
	}
}

func (m *OwnerSessionLeaseManager) closeEntryLocked(entry *ownerSessionLeaseEntry, now time.Time) {
	if entry == nil || entry.closed {
		return
	}
	entry.closed = true
	entry.retireAt = now.Add(m.ttl)
	_ = m.registry.CloseMachineOwnerSession(m.machineID, entry.lease.OwnerSessionID)
}

func (m *OwnerSessionLeaseManager) findOwnerSessionLocked(ownerSessionID string) (*ownerSessionLeaseEntry, bool) {
	for _, entry := range m.leases {
		if entry.lease.OwnerSessionID == ownerSessionID && !entry.closed {
			return entry, true
		}
	}
	return nil, false
}

func (m *OwnerSessionLeaseManager) Close() error {
	if m == nil {
		return nil
	}
	now := m.now().UTC()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	for _, entry := range m.leases {
		m.closeEntryLocked(entry, now)
		_ = m.registry.ReleaseMachineOwnerSession(m.machineID, entry.lease.OwnerSessionID)
	}
	m.leases = make(map[string]*ownerSessionLeaseEntry)
	m.idempotency = make(map[string]ownerSessionLeaseReplay)
	m.mu.Unlock()
	return nil
}

// OwnerSessionLeaseRequest is the strict body accepted by the local endpoint.
type OwnerSessionLeaseRequest struct {
	OwnerSessionID string      `json:"owner_session_id,omitempty"`
	Target         LeaseTarget `json:"target"`
}

// ServeHTTP handles one authenticated owner-session lease request over hostd's
// already authenticated loopback HTTP service. The local control token and
// lease token are both required; no browser or server credential is accepted.
func (m *OwnerSessionLeaseManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if m == nil || r == nil || r.URL == nil || !secureTokenEqual(r.Header.Get("Authorization"), "Bearer "+m.controlToken) {
		writeOwnerSessionLeaseError(w, http.StatusUnauthorized, ErrOwnerSessionLeaseUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/preview-owner-sessions")
	path = strings.Trim(path, "/")
	switch {
	case r.Method == http.MethodPost && path == "":
		if !validLocalTrace(r.Header.Get("Idempotency-Key")) {
			writeOwnerSessionLeaseError(w, http.StatusBadRequest, ErrOwnerSessionLeaseInvalid)
			return
		}
		var request OwnerSessionLeaseRequest
		if err := decodeOwnerSessionLeaseJSON(r.Body, &request); err != nil {
			writeOwnerSessionLeaseError(w, http.StatusBadRequest, err)
			return
		}
		lease, err := m.Acquire(request, r.Header.Get("Idempotency-Key"))
		if err != nil {
			writeOwnerSessionLeaseError(w, ownerSessionLeaseStatus(err), err)
			return
		}
		writeOwnerSessionLeaseJSON(w, http.StatusCreated, lease)
	case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && validLeaseID(path):
		token := strings.TrimSpace(r.Header.Get("X-Paperboat-Owner-Session-Token"))
		if token == "" {
			writeOwnerSessionLeaseError(w, http.StatusUnauthorized, ErrOwnerSessionLeaseUnauthorized)
			return
		}
		if r.Method == http.MethodPut {
			if !emptyOwnerSessionLeaseBody(r.Body) {
				writeOwnerSessionLeaseError(w, http.StatusBadRequest, ErrOwnerSessionLeaseInvalid)
				return
			}
			lease, err := m.Heartbeat(path, token)
			if err != nil {
				writeOwnerSessionLeaseError(w, ownerSessionLeaseStatus(err), err)
				return
			}
			writeOwnerSessionLeaseJSON(w, http.StatusOK, lease)
		} else {
			if !emptyOwnerSessionLeaseBody(r.Body) {
				writeOwnerSessionLeaseError(w, http.StatusBadRequest, ErrOwnerSessionLeaseInvalid)
				return
			}
			if err := m.Release(path, token); err != nil {
				writeOwnerSessionLeaseError(w, ownerSessionLeaseStatus(err), err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		writeOwnerSessionLeaseError(w, http.StatusMethodNotAllowed, ErrOwnerSessionLeaseInvalid)
	}
}

func ownerSessionLeaseRequestHash(request OwnerSessionLeaseRequest) (string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return "", errors.Join(ErrOwnerSessionLeaseInvalid, err)
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:]), nil
}

func (m *OwnerSessionLeaseManager) randomID(prefix string) (string, error) {
	value := make([]byte, 18)
	if _, err := io.ReadFull(m.random, value); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func (m *OwnerSessionLeaseManager) randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(m.random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func secureTokenEqual(left, right string) bool {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func validLocalTrace(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func decodeOwnerSessionLeaseJSON(body io.ReadCloser, value any) error {
	if body == nil || value == nil {
		return ErrOwnerSessionLeaseInvalid
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, ownerSessionLeaseBodyLimit+1))
	if err != nil || len(data) > ownerSessionLeaseBodyLimit || rejectAttachmentDuplicateFields(data) != nil {
		return ErrOwnerSessionLeaseInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrOwnerSessionLeaseInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrOwnerSessionLeaseInvalid
	}
	return nil
}

func emptyOwnerSessionLeaseBody(body io.ReadCloser) bool {
	if body == nil {
		return true
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, ownerSessionLeaseBodyLimit+1))
	return err == nil && len(data) <= ownerSessionLeaseBodyLimit && len(strings.TrimSpace(string(data))) == 0
}

func ownerSessionLeaseStatus(err error) int {
	switch {
	case errors.Is(err, ErrOwnerSessionLeaseUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrOwnerSessionLeaseConflict):
		return http.StatusConflict
	case errors.Is(err, ErrOwnerSessionLeaseLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrOwnerSessionLeaseLost):
		return http.StatusGone
	default:
		return http.StatusBadRequest
	}
}

func writeOwnerSessionLeaseJSON(w http.ResponseWriter, status int, lease OwnerSessionLease) {
	lease.idempotencyKey = ""
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(lease)
}

func writeOwnerSessionLeaseError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	code := "invalid_owner_session_lease"
	switch {
	case errors.Is(err, ErrOwnerSessionLeaseUnauthorized):
		code = "owner_session_unauthorized"
	case errors.Is(err, ErrOwnerSessionLeaseConflict):
		code = "owner_session_conflict"
	case errors.Is(err, ErrOwnerSessionLeaseLimit):
		code = "owner_session_limit"
	case errors.Is(err, ErrOwnerSessionLeaseLost):
		code = "owner_session_lost"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}

// LocalOwnerSessionEndpoint validates the loopback URL read from hostd's
// worker-local descriptor before a CLI sends its local control token.
func LocalOwnerSessionEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	if ip := parsed.Hostname(); ip != "127.0.0.1" && ip != "::1" {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	return parsed, nil
}

var _ http.Handler = (*OwnerSessionLeaseManager)(nil)

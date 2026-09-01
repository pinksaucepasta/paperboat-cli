package preview

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

const (
	PrivateTCPAccessSchema       = "paperboat.private-tcp-access/v1"
	privateTCPAccessBodyLimit    = 4 << 10
	defaultPrivateTCPAccessLimit = 64
)

var (
	ErrPrivateTCPAccessInvalid        = errors.New("invalid private TCP access request")
	ErrPrivateTCPAccessAuthentication = errors.New("private TCP access authentication required")
	ErrPrivateTCPAccessForbidden      = errors.New("private TCP access forbidden")
	ErrPrivateTCPAccessNotFound       = errors.New("private TCP route not found")
	ErrPrivateTCPAccessUnavailable    = errors.New("private TCP access temporarily unavailable")
	ErrPrivateTCPAccessClosed         = errors.New("private TCP access manager closed")
)

type PrivateTCPAccessManagerConfig struct {
	Runtime       *MachinePreviewRuntime
	ControlToken  string
	RunContext    context.Context
	MaximumActive int
	resolve       func(context.Context, string) (string, string, error)
	start         func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error)
	newID         func() (string, error)
}

type privateTCPAccessProxy interface {
	Close() error
	AccessURL() string
}
type machinePrivateTCPProxy struct{ proxy *privatepreviewproxy.Proxy }

func (p machinePrivateTCPProxy) Close() error      { return p.proxy.Close() }
func (p machinePrivateTCPProxy) AccessURL() string { return p.proxy.URL }

type PrivateTCPAccessManager struct {
	token      string
	runContext context.Context
	maximum    int
	resolve    func(context.Context, string) (string, string, error)
	start      func(context.Context, PrivateTCPAccessRequest) (privateTCPAccessProxy, error)
	newID      func() (string, error)
	mu         sync.Mutex
	closed     bool
	pending    int
	active     map[string]*privateTCPAccessSession
}

type privateTCPAccessSession struct {
	ID, TunnelID, RouteID, ListenAddress string
	proxy                                privateTCPAccessProxy
}
type privateTCPAccessRequestDocument struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Selector      string `json:"selector"`
	ListenAddress string `json:"listen_address"`
}
type privateTCPAccessResponseDocument struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	TunnelID      string `json:"tunnel_id"`
	RouteID       string `json:"route_id"`
	ListenAddress string `json:"listen_address"`
}

func NewPrivateTCPAccessManager(config PrivateTCPAccessManagerConfig) (*PrivateTCPAccessManager, error) {
	if config.RunContext == nil || strings.TrimSpace(config.ControlToken) == "" {
		return nil, ErrPrivateTCPAccessInvalid
	}
	if config.MaximumActive == 0 {
		config.MaximumActive = defaultPrivateTCPAccessLimit
	}
	if config.MaximumActive < 1 || config.MaximumActive > 1024 {
		return nil, ErrPrivateTCPAccessInvalid
	}
	resolve, start := config.resolve, config.start
	if config.Runtime != nil {
		if resolve == nil {
			resolve = config.Runtime.resolvePrivateTCPRoute
		}
		if start == nil {
			start = func(ctx context.Context, request PrivateTCPAccessRequest) (privateTCPAccessProxy, error) {
				proxy, err := config.Runtime.StartPrivateTCPAccess(ctx, request)
				if err != nil {
					return nil, err
				}
				return machinePrivateTCPProxy{proxy}, nil
			}
		}
	}
	if resolve == nil || start == nil {
		return nil, ErrPrivateTCPAccessInvalid
	}
	newID := config.newID
	if newID == nil {
		newID = newPrivateAccessIdentifier
	}
	manager := &PrivateTCPAccessManager{token: strings.TrimSpace(config.ControlToken), runContext: config.RunContext, maximum: config.MaximumActive, resolve: resolve, start: start, newID: newID, active: make(map[string]*privateTCPAccessSession)}
	go func() { <-config.RunContext.Done(); _ = manager.Close() }()
	return manager, nil
}

func (r *MachinePreviewRuntime) resolvePrivateTCPRoute(ctx context.Context, selector string) (string, string, error) {
	if r == nil || ctx == nil || !validPrivateTCPSelector(selector) {
		return "", "", ErrPrivateTCPAccessInvalid
	}
	selector = strings.TrimSpace(selector)
	r.mu.Lock()
	if r.closed || r.private == nil {
		r.mu.Unlock()
		return "", "", ErrPrivateTCPAccessUnavailable
	}
	source := r.private
	r.mu.Unlock()
	source.mu.RLock()
	discovery := source.discovery
	closed := source.closed
	source.mu.RUnlock()
	if closed || discovery == nil {
		return "", "", ErrPrivateTCPAccessUnavailable
	}
	admissions, err := discovery.snapshot(ctx)
	if err != nil {
		return "", "", mapPrivateTCPAccessError(err)
	}
	selected, err := resolvePrivateTCPAdmission(admissions, selector)
	if err != nil {
		return "", "", err
	}
	return selected.RouteID, selected.TunnelID, nil
}

func resolvePrivateTCPAdmission(admissions []accessorAdmission, selector string) (accessorAdmission, error) {
	if !validPrivateTCPSelector(selector) {
		return accessorAdmission{}, ErrPrivateTCPAccessInvalid
	}
	selector = strings.TrimSpace(selector)
	var selected *accessorAdmission
	for i := range admissions {
		a := &admissions[i]
		if a.ResourceKind != "tunnel" || a.Protocol != "private_tcp" {
			continue
		}
		if !matchesPrivateTCPSelector(*a, selector) {
			continue
		}
		if selected != nil {
			return accessorAdmission{}, ErrPrivateTCPAccessUnavailable
		}
		selected = a
	}
	if selected == nil {
		return accessorAdmission{}, ErrPrivateTCPAccessNotFound
	}
	return *selected, nil
}

func matchesPrivateTCPSelector(admission accessorAdmission, selector string) bool {
	return admission.RouteID == selector || admission.ResourceID == selector || admission.TunnelID == selector || admission.TunnelName == selector || admission.RouteName == selector
}

func (m *PrivateTCPAccessManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if m == nil || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))), []byte(m.token)) != 1 {
		writePrivateTCPAccessError(w, http.StatusUnauthorized, "authentication_required", "Authentication with the local hostd control token is required.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/private-tcp-access")
	switch {
	case r.Method == http.MethodPost && path == "":
		m.handleStart(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/") && len(path) > 1:
		m.handleDelete(w, strings.TrimPrefix(path, "/"))
	default:
		writePrivateTCPAccessError(w, http.StatusNotFound, "not_found", "Private TCP access endpoint was not found.")
	}
}

func (m *PrivateTCPAccessManager) handleStart(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, privateTCPAccessBodyLimit+1))
	if err != nil || len(body) == 0 || len(body) > privateTCPAccessBodyLimit || rejectAttachmentDuplicateFields(body) != nil {
		writePrivateTCPAccessError(w, http.StatusBadRequest, "invalid_request", "The private TCP access request is invalid.")
		return
	}
	var document privateTCPAccessRequestDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != PrivateTCPAccessSchema || document.Kind != "private_tcp_access_request" || !validPrivateTCPSelector(document.Selector) {
		writePrivateTCPAccessError(w, http.StatusBadRequest, "invalid_request", "The private TCP access request is invalid.")
		return
	}
	listenPort, err := privateTCPListenPort(document.ListenAddress)
	if err != nil {
		writePrivateTCPAccessError(w, http.StatusBadRequest, "invalid_listen_address", "The listen address must be literal loopback.")
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "runtime_unavailable", "Stable hostd is shutting down.")
		return
	}
	if len(m.active)+m.pending >= m.maximum {
		m.mu.Unlock()
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "capacity_exhausted", "The private TCP access limit is reached.")
		return
	}
	m.pending++
	m.mu.Unlock()
	reserved := true
	defer func() {
		if reserved {
			m.mu.Lock()
			m.pending--
			m.mu.Unlock()
		}
	}()
	routeID, tunnelID, err := m.resolve(r.Context(), document.Selector)
	if err != nil {
		writeMappedPrivateTCPAccessError(w, err)
		return
	}
	proxy, err := m.start(r.Context(), PrivateTCPAccessRequest{RouteID: routeID, ListenPort: listenPort, MaximumConnections: 128})
	if err != nil {
		writeMappedPrivateTCPAccessError(w, mapPrivateTCPAccessError(err))
		return
	}
	listenAddress, err := privateTCPProxyAddress(proxy.AccessURL())
	if err != nil {
		_ = proxy.Close()
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "runtime_unavailable", "The authorized loopback listener could not be started.")
		return
	}
	id, err := m.newID()
	if err != nil || !validPrivateTCPSelector(id) {
		_ = proxy.Close()
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "runtime_unavailable", "The access session could not be created.")
		return
	}
	session := &privateTCPAccessSession{ID: "access_" + id, TunnelID: tunnelID, RouteID: routeID, ListenAddress: listenAddress, proxy: proxy}
	m.mu.Lock()
	m.pending--
	reserved = false
	if _, exists := m.active[session.ID]; m.closed || len(m.active) >= m.maximum || exists {
		m.mu.Unlock()
		_ = proxy.Close()
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "capacity_exhausted", "The private TCP access limit is reached.")
		return
	}
	m.active[session.ID] = session
	m.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(privateTCPAccessResponseDocument{Schema: PrivateTCPAccessSchema, Kind: "private_tcp_access", ID: session.ID, TunnelID: tunnelID, RouteID: routeID, ListenAddress: listenAddress})
}

func (m *PrivateTCPAccessManager) handleDelete(w http.ResponseWriter, id string) {
	if !validPrivateTCPSelector(id) {
		writePrivateTCPAccessError(w, http.StatusNotFound, "not_found", "Private TCP access session was not found.")
		return
	}
	m.mu.Lock()
	session := m.active[id]
	delete(m.active, id)
	m.mu.Unlock()
	if session != nil {
		_ = session.proxy.Close()
	}
	w.Header().Del("Content-Type")
	w.WriteHeader(http.StatusNoContent)
}

func (m *PrivateTCPAccessManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	sessions := make([]*privateTCPAccessSession, 0, len(m.active))
	for _, session := range m.active {
		sessions = append(sessions, session)
	}
	clear(m.active)
	m.mu.Unlock()
	var result error
	for _, session := range sessions {
		result = errors.Join(result, session.proxy.Close())
	}
	return result
}

func validPrivateTCPSelector(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n/\\")
}
func privateTCPListenPort(value string) (uint16, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return 0, ErrPrivateTCPAccessInvalid
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || (host != "127.0.0.1" && host != "::1") {
		return 0, ErrPrivateTCPAccessInvalid
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(parsed, 10) != port {
		return 0, ErrPrivateTCPAccessInvalid
	}
	return uint16(parsed), nil
}
func privateTCPProxyAddress(raw string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", ErrPrivateTCPAccessUnavailable
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	if err != nil || host != "127.0.0.1" {
		return "", ErrPrivateTCPAccessUnavailable
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return "", ErrPrivateTCPAccessUnavailable
	}
	return endpoint.Host, nil
}
func mapPrivateTCPAccessError(err error) error {
	switch {
	case errors.Is(err, privatepreviewproxy.ErrAccessAuthentication):
		return ErrPrivateTCPAccessAuthentication
	case errors.Is(err, privatepreviewproxy.ErrAccessForbidden):
		return ErrPrivateTCPAccessForbidden
	case errors.Is(err, ErrPrivateTCPAccessNotFound):
		return ErrPrivateTCPAccessNotFound
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrPrivateTCPAccessUnavailable
	}
}
func writeMappedPrivateTCPAccessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPrivateTCPAccessAuthentication):
		writePrivateTCPAccessError(w, http.StatusUnauthorized, "authentication_required", "Paperboat authentication is required.")
	case errors.Is(err, ErrPrivateTCPAccessForbidden):
		writePrivateTCPAccessError(w, http.StatusForbidden, "access_forbidden", "Private access is not allowed.")
	case errors.Is(err, ErrPrivateTCPAccessNotFound):
		// Do not disclose whether the selector names an absent, paused, or
		// cross-account route. An authenticated caller without a current
		// authorization receives the same non-enumerating denial.
		writePrivateTCPAccessError(w, http.StatusForbidden, "access_forbidden", "Private access is not allowed.")
	default:
		writePrivateTCPAccessError(w, http.StatusServiceUnavailable, "runtime_unavailable", "Private access is temporarily unavailable.")
	}
}
func writePrivateTCPAccessError(w http.ResponseWriter, status int, code, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

var _ http.Handler = (*PrivateTCPAccessManager)(nil)

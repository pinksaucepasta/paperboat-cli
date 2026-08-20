package codexsession

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

const MaxMessageBytes int64 = 128 << 20

type HandlerConfig struct {
	Manager        *Manager
	Authorizer     server.AuthorizerFactory
	MaxConnections int
}

type Handler struct {
	config HandlerConfig
	slots  chan struct{}
}

type ManagementHandler struct {
	manager    *Manager
	authorizer server.AuthorizerFactory
}

func NewManagementHandler(manager *Manager, authorizer server.AuthorizerFactory) (*ManagementHandler, error) {
	if manager == nil || authorizer == nil {
		return nil, ErrInvalid
	}
	return &ManagementHandler{manager: manager, authorizer: authorizer}, nil
}

func (h *ManagementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("session_id")
	auth, release, ok := authorizeHTTP(r, h.authorizer, "codex.manage.v1")
	defer release()
	if !ok || auth.SessionID != id {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/directories") {
		page, err := h.manager.Directories(r.URL.Query().Get("path"), r.URL.Query().Get("cursor"), 100)
		if err != nil {
			writeManagementError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(page)
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.manager.Stop(r.Context(), id); err != nil {
			writeManagementError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body struct {
		Path           string    `json:"path"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var result any
	var err error
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/renew"):
		err = h.manager.Renew(id, body.LeaseExpiresAt)
		result = map[string]any{"lease_expires_at": body.LeaseExpiresAt.UTC()}
	case r.Method == http.MethodPost:
		result, err = h.manager.Prepare(r.Context(), id, body.Path, body.LeaseExpiresAt)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err != nil {
		writeManagementError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func writeManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case errors.Is(err, ErrLimitReached):
		http.Error(w, "limit_reached", http.StatusTooManyRequests)
	case errors.Is(err, ErrWorkspaceEscape), errors.Is(err, ErrInvalid):
		http.Error(w, "workspace_boundary", http.StatusBadRequest)
	case errors.Is(err, ErrCodexUnavailable):
		http.Error(w, "codex_unavailable", http.StatusServiceUnavailable)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func NewHandler(config HandlerConfig) (*Handler, error) {
	if config.MaxConnections == 0 {
		config.MaxConnections = 16
	}
	if config.Manager == nil || config.Authorizer == nil || config.MaxConnections < 1 {
		return nil, ErrInvalid
	}
	return &Handler{config: config, slots: make(chan struct{}, config.MaxConnections)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("session_id")
	auth, release, authorized := authorizeHTTP(r, h.config.Authorizer, "codex.connect.v1")
	defer release()
	if !authorized {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if auth.SessionID != id {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if len(r.Header.Values("Origin")) != 0 {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	socket, err := h.config.Manager.Socket(id)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	local, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	local.SetReadLimit(MaxMessageBytes)
	transport := &http.Transport{ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialCodexAppServer(ctx, socket)
	}}
	defer transport.CloseIdleConnections()
	remoteURL := "ws://localhost"
	if strings.HasPrefix(socket, "ws://127.0.0.1:") {
		remoteURL = socket
	}
	remote, _, err := websocket.Dial(context.WithoutCancel(r.Context()), remoteURL, &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		_ = local.Close(websocket.StatusInternalError, "remote_unavailable")
		return
	}
	remote.SetReadLimit(MaxMessageBytes)
	proxy(r.Context(), local, remote)
}

func authorizeHTTP(r *http.Request, factory server.AuthorizerFactory, capability string) (server.Authorization, func(), bool) {
	token, ok := bearer(r.Header.Values("Authorization"))
	if !ok {
		return server.Authorization{}, func() {}, false
	}
	authorizer, err := factory(token)
	if err != nil || authorizer == nil {
		return server.Authorization{}, func() {}, false
	}
	release := func() {}
	if closer, ok := authorizer.(server.AuthorizationCloser); ok {
		release = closer.CloseAuthorization
	}
	auth, err := authorizer.Authorize(r.Context(), protocol.Frame{Type: "request", RequestID: "codex-http", Version: protocol.ProtocolVersion, OperationID: "codex-http", Capability: capability, Payload: json.RawMessage(`{}`)})
	return auth, release, err == nil
}

func proxy(parent context.Context, a, b *websocket.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var once sync.Once
	closeBoth := func(status websocket.StatusCode, reason string) {
		once.Do(func() { _ = a.Close(status, reason); _ = b.Close(status, reason) })
	}
	errs := make(chan error, 2)
	copyFrames := func(dst, src *websocket.Conn) {
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				errs <- err
				return
			}
			writeCtx, writeCancel := context.WithTimeout(ctx, 30*time.Second)
			err = dst.Write(writeCtx, typ, data)
			writeCancel()
			if err != nil {
				errs <- err
				return
			}
		}
	}
	go copyFrames(a, b)
	go copyFrames(b, a)
	err := <-errs
	status := websocket.CloseStatus(err)
	if status < 1000 {
		status = websocket.StatusGoingAway
	}
	reason := "closed"
	if !errors.Is(err, context.Canceled) && status != websocket.StatusNormalClosure {
		reason = "connection_lost"
	}
	closeBoth(status, reason)
}

func bearer(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	returnValue := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && len(parts[1]) >= 16 && len(parts[1]) <= 16<<10
	if !returnValue {
		return "", false
	}
	return parts[1], true
}

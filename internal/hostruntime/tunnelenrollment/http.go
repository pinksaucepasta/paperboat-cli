package tunnelenrollment

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
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
)

const localBodyLimit = 8 << 10

type requestDocument struct {
	Schema   string `json:"schema"`
	Kind     string `json:"kind"`
	TunnelID string `json:"tunnel_id"`
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if m == nil || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))), []byte(m.controlToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnel-connectors/enroll" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	body, err := io.ReadAll(io.LimitReader(r.Body, localBodyLimit+1))
	if err != nil || len(body) == 0 || len(body) > localBodyLimit || !safeID(key) || rejectDuplicateJSON(body) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var document requestDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != Schema || document.Kind != "tunnel_connector_enrollment_request" || connectorprotocol.ValidateIdentifier(document.TunnelID) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	projection, err := m.Enroll(r.Context(), document.TunnelID, key)
	if err != nil {
		switch {
		case err == context.Canceled || err == context.DeadlineExceeded:
			writeError(w, http.StatusServiceUnavailable, "runtime_unavailable")
		case errors.Is(err, ErrAuthentication):
			writeError(w, http.StatusUnauthorized, "authentication_required")
		case errors.Is(err, ErrForbidden):
			writeError(w, http.StatusForbidden, "forbidden")
		case errors.Is(err, ErrConflict):
			writeError(w, http.StatusConflict, "enrollment_conflict")
		case errors.Is(err, ErrActivation):
			writeError(w, http.StatusServiceUnavailable, "activation_unavailable")
		case errors.Is(err, ErrSecretStore):
			writeError(w, http.StatusServiceUnavailable, "credential_store_unavailable")
		default:
			writeError(w, http.StatusServiceUnavailable, "runtime_unavailable")
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(projection)
}
func writeError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}

type LocalClient struct {
	base  *url.URL
	token string
	http  *http.Client
}

func NewLocalClient(endpoint, token string, client *http.Client) (*LocalClient, error) {
	base, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || base.Scheme != "http" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || strings.TrimSpace(token) == "" {
		return nil, ErrInvalid
	}
	host, port, err := net.SplitHostPort(base.Host)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return nil, ErrInvalid
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrInvalid
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	} else {
		copy := *client
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrInvalid }
	return &LocalClient{base: base, token: strings.TrimSpace(token), http: client}, nil
}
func (c *LocalClient) Enroll(ctx context.Context, tunnel, key string) (Projection, error) {
	if c == nil || ctx == nil || connectorprotocol.ValidateIdentifier(tunnel) != nil || !safeID(key) {
		return Projection{}, ErrInvalid
	}
	body, _ := json.Marshal(requestDocument{Schema: Schema, Kind: "tunnel_connector_enrollment_request", TunnelID: tunnel})
	endpoint := *c.base
	endpoint.Path = "/v1/tunnel-connectors/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Projection{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Projection{}, ctx.Err()
		}
		return Projection{}, ErrUnavailable
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, localBodyLimit+1))
	if err != nil || len(raw) > localBodyLimit {
		return Projection{}, ErrUnavailable
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &envelope)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return Projection{}, ErrAuthentication
		case http.StatusForbidden:
			return Projection{}, ErrForbidden
		case http.StatusConflict:
			return Projection{}, ErrConflict
		default:
			if envelope.Error.Code == "activation_unavailable" {
				return Projection{}, ErrActivation
			}
			if envelope.Error.Code == "credential_store_unavailable" {
				return Projection{}, ErrSecretStore
			}
			return Projection{}, ErrUnavailable
		}
	}
	if rejectDuplicateJSON(raw) != nil {
		return Projection{}, ErrUnavailable
	}
	var out Projection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(&struct{}{}) != io.EOF || !out.valid() || out.TunnelID != tunnel {
		return Projection{}, ErrUnavailable
	}
	return out, nil
}

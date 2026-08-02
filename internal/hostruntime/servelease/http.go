package servelease

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type Handler struct {
	Manager *Manager
	Token   string
}

type request struct {
	Schema  string `json:"schema_version"`
	Action  string `json:"action"`
	LeaseID string `json:"lease_id,omitempty"`
	Name    string `json:"name"`
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Manager == nil || h.Token == "" || r.Header.Get("Authorization") != "Bearer "+h.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": ProtocolVersion, "active_leases": h.Manager.Count()})
		return
	}
	var input request
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Schema != ProtocolVersion || input.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var lease Lease
	var err error
	switch input.Action {
	case "acquire":
		if input.LeaseID != "" {
			err = ErrInvalid
		} else {
			lease, err = h.Manager.Acquire(input.Name)
		}
	case "renew":
		lease, err = h.Manager.Renew(input.LeaseID, input.Name)
	case "release":
		err = h.Manager.Release(input.LeaseID, input.Name)
	default:
		err = ErrInvalid
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrConflict) {
			status = http.StatusConflict
		} else if errors.Is(err, ErrLeaseLost) {
			status = http.StatusGone
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": leaseErrorCode(err)}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": ProtocolVersion, "lease": lease})
}

func leaseErrorCode(err error) string {
	if errors.Is(err, ErrConflict) {
		return "serve_lease_conflict"
	}
	if errors.Is(err, ErrLeaseLost) {
		return "serve_lease_lost"
	}
	return "invalid_request"
}

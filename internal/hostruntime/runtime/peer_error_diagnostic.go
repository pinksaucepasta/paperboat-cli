//go:build darwin || linux || windows

package runtime

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

const peerLastErrorSchema = "paperboat.peer-last-error/v1"

type peerLastErrorRecord struct {
	Schema string    `json:"schema"`
	At     time.Time `json:"at"`
	Class  string    `json:"class"`
}

type peerLastErrorWrite struct {
	root string
	body []byte
}

type peerLastErrorWriter func(string, []byte) error

type peerLastErrorRecorder struct {
	start sync.Once
	wake  chan struct{}
	write peerLastErrorWriter

	mu      sync.Mutex
	latest  peerLastErrorWrite
	pending bool
}

var productionPeerOutcomeRecorder = newPeerLastErrorRecorder(func(root string, body []byte) error {
	return writePeerLastError(root, body)
})

func newPeerLastErrorRecorder(write peerLastErrorWriter) *peerLastErrorRecorder {
	return &peerLastErrorRecorder{wake: make(chan struct{}, 1), write: write}
}

func (r *peerLastErrorRecorder) record(item peerLastErrorWrite) {
	if r == nil || r.write == nil || item.root == "" || len(item.body) == 0 {
		return
	}
	r.mu.Lock()
	r.latest = item
	r.pending = true
	r.mu.Unlock()
	r.start.Do(func() { go r.run() })
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *peerLastErrorRecorder) run() {
	for range r.wake {
		r.mu.Lock()
		if !r.pending {
			r.mu.Unlock()
			continue
		}
		item := r.latest
		r.pending = false
		r.mu.Unlock()
		if err := r.write(item.root, item.body); err != nil {
			slog.Warn("peer transport durable diagnostic failed", "error", err)
		}
	}
}

func observeProductionPeerError(stateRoot string, err error) {
	slog.Error("peer transport attempt failed", "error", err)
	class, ok := peerTransferErrorClass(err)
	if !ok {
		return
	}
	recordProductionPeerOutcome(stateRoot, class)
}

func recordProductionPeerOutcome(stateRoot, class string) {
	if stateRoot == "" || class == "" {
		return
	}
	body, marshalErr := json.Marshal(peerLastErrorRecord{Schema: peerLastErrorSchema, At: time.Now().UTC(), Class: class})
	if marshalErr != nil {
		return
	}
	body = append(body, '\n')
	productionPeerOutcomeRecorder.record(peerLastErrorWrite{root: stateRoot, body: body})
}

func peerTransferErrorClass(err error) (string, bool) {
	switch {
	case errors.Is(err, transfercrypto.ErrControlContext):
		return "transfer_key_context_rejected", true
	case errors.Is(err, transfercrypto.ErrControlRead):
		return "transfer_key_read_failed", true
	case errors.Is(err, transfercrypto.ErrControlRejected):
		return "transfer_key_binding_rejected", true
	case errors.Is(err, transfercrypto.ErrControlStore):
		switch {
		case errors.Is(err, clientconfig.ErrCredentialRequiresInteractiveLogin):
			return "transfer_key_store_interactive_login_required", true
		case errors.Is(err, clientconfig.ErrCredentialStoreUnavailable):
			return "transfer_key_store_credential_unavailable", true
		case errors.Is(err, os.ErrPermission):
			return "transfer_key_store_permission_denied", true
		case errors.Is(err, os.ErrNotExist):
			return "transfer_key_store_path_unavailable", true
		case errors.Is(err, transfercrypto.ErrInvalid):
			return "transfer_key_store_invalid", true
		default:
			return "transfer_key_store_failed", true
		}
	case errors.Is(err, transfercrypto.ErrControlAck):
		return "transfer_key_ack_failed", true
	default:
		return "", false
	}
}

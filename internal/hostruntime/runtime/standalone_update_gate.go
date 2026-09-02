//go:build darwin || linux || windows

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

var errStandaloneUpdateGate = errors.New("standalone update gate unavailable")

const standaloneUpdateGateSchema = "paperboat.standalone-update-gate/v1"

type standaloneUpdateGateConfig struct {
	MachineID string
	StatePath string
	Health    http.Handler
	Workloads func() hostdproto.WorkloadStatus
	Now       func() time.Time
}

type standaloneUpdateGate struct {
	config       standaloneUpdateGateConfig
	mu           sync.Mutex
	transactions map[string]standaloneUpdateTransaction
}

type standaloneUpdateTransaction struct {
	Version            string
	Manifest           string
	Path               string
	Status             int
	Samples            uint16
	Target             hostdproto.UpdateGateTargetBinding
	Created            time.Time
	PolicyBound        bool
	Drained            bool
	Committed          bool
	WorkloadGeneration uint64
	ProtectedWorkloads uint64
}

type standaloneUpdateGateDisk struct {
	Schema       string                                 `json:"schema"`
	Transactions map[string]standaloneUpdateTransaction `json:"transactions"`
}

func newStandaloneUpdateGate(config standaloneUpdateGateConfig) (*standaloneUpdateGate, error) {
	if config.MachineID == "" || !filepath.IsAbs(config.StatePath) || config.Health == nil || config.Workloads == nil {
		return nil, errStandaloneUpdateGate
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(config.StatePath), 0o700); err != nil {
		return nil, err
	}
	gate := &standaloneUpdateGate{config: config, transactions: make(map[string]standaloneUpdateTransaction)}
	if err := gate.load(); err != nil {
		return nil, err
	}
	return gate, nil
}

func (g *standaloneUpdateGate) target() hostdproto.UpdateGateTargetBinding {
	return hostdproto.UpdateGateTargetBinding{Scope: hostdproto.UpdateGateScopeStandalone, MachineID: g.config.MachineID, FailureDomain: "standalone"}
}

func (g *standaloneUpdateGate) HandleUpdateGate(ctx context.Context, request hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error) {
	if g == nil || ctx == nil || request.Validate() != nil {
		return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.purge()
	target := g.target()
	if request.Operation != hostdproto.UpdateGateTarget && (request.ExpectedTarget == nil || *request.ExpectedTarget != target) {
		return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
	}
	transaction, exists := g.transactions[request.TransactionID]
	switch request.Operation {
	case hostdproto.UpdateGateTarget:
		if exists {
			if transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 {
				return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
			}
			return hostdproto.UpdateGateResponse{Target: target}, nil
		}
		if len(g.transactions) >= 128 {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		g.transactions[request.TransactionID] = standaloneUpdateTransaction{Version: request.Version, Manifest: request.ManifestSHA256, Target: target, Created: g.config.Now().UTC()}
	case hostdproto.UpdateGateCandidate:
		if !exists || transaction.Committed || transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 || transaction.Target != target || transaction.PolicyBound && (transaction.Path != request.Path || transaction.Status != request.ExpectedStatus || transaction.Samples != request.Samples) {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		if err := g.probe(ctx, request); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		transaction.Path, transaction.Status, transaction.Samples, transaction.PolicyBound = request.Path, request.ExpectedStatus, request.Samples, true
		g.transactions[request.TransactionID] = transaction
	case hostdproto.UpdateGateDrain:
		if !exists || transaction.Committed || !transaction.PolicyBound || transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 || transaction.Target != target {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		workloads := g.config.Workloads()
		if workloads.Generation == 0 && workloads.Protected != 0 {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		// Sessions, previews, tunnels, and transfers are owned by stable hostd,
		// not by the replaceable worker. Their presence must therefore fence the
		// cutover, not block every update forever. Record the exact stable-host
		// snapshot and require it to remain unchanged through activation.
		transaction.Drained = true
		transaction.WorkloadGeneration = workloads.Generation
		transaction.ProtectedWorkloads = workloads.Protected
		g.transactions[request.TransactionID] = transaction
	case hostdproto.UpdateGateStability:
		if !exists || transaction.Committed || !transaction.Drained || transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 || transaction.Path != request.Path || transaction.Status != request.ExpectedStatus || transaction.Samples != request.Samples || transaction.Target != target {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		workloads := g.config.Workloads()
		if workloads.Generation != transaction.WorkloadGeneration || workloads.Protected != transaction.ProtectedWorkloads {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		deadline := g.config.Now().Add(time.Duration(request.WindowMillis) * time.Millisecond)
		for {
			probe := request
			probe.TimeoutMillis = request.IntervalMillis
			if err := g.probe(ctx, probe); err != nil {
				return hostdproto.UpdateGateResponse{}, err
			}
			if !g.config.Now().Before(deadline) {
				break
			}
			timer := time.NewTimer(time.Duration(request.IntervalMillis) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return hostdproto.UpdateGateResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
	case hostdproto.UpdateGateRollback:
		// Drain may fail before it records Drained=true. The updater still issues
		// rollback to close that exact transaction and re-probe the unchanged
		// active path. Requiring Drained here strands every such recovery forever.
		if !exists || transaction.Committed || !transaction.PolicyBound || transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 || transaction.Path != request.Path || transaction.Status != request.ExpectedStatus || transaction.Samples != request.Samples || transaction.Target != target {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		if err := g.probe(ctx, request); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		delete(g.transactions, request.TransactionID)
	case hostdproto.UpdateGateCommit:
		if exists && transaction.Committed {
			if transaction.Version == request.Version && transaction.Manifest == request.ManifestSHA256 && transaction.Target == target {
				return hostdproto.UpdateGateResponse{Target: target}, nil
			}
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		if !exists || !transaction.PolicyBound || !transaction.Drained || transaction.Version != request.Version || transaction.Manifest != request.ManifestSHA256 || transaction.Target != target {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		workloads := g.config.Workloads()
		if workloads.Generation != transaction.WorkloadGeneration || workloads.Protected != transaction.ProtectedWorkloads {
			return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
		}
		transaction.Drained, transaction.Committed = false, true
		g.transactions[request.TransactionID] = transaction
	default:
		return hostdproto.UpdateGateResponse{}, errStandaloneUpdateGate
	}
	if err := g.persist(); err != nil {
		return hostdproto.UpdateGateResponse{}, err
	}
	return hostdproto.UpdateGateResponse{Target: target}, nil
}

func (g *standaloneUpdateGate) probe(ctx context.Context, request hostdproto.UpdateGateRequest) error {
	for range request.Samples {
		recorder := &boundedResponseRecorder{header: make(http.Header), limit: 64 << 10}
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1"+request.Path, nil)
		if err != nil {
			return errStandaloneUpdateGate
		}
		httpRequest.RemoteAddr = "127.0.0.1:1"
		g.config.Health.ServeHTTP(recorder, httpRequest)
		if recorder.status != request.ExpectedStatus || recorder.overflow {
			return errStandaloneUpdateGate
		}
	}
	return nil
}

type boundedResponseRecorder struct {
	header   http.Header
	status   int
	written  int
	limit    int
	overflow bool
}

func (r *boundedResponseRecorder) Header() http.Header { return r.header }
func (r *boundedResponseRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *boundedResponseRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.written += len(body)
	if r.written > r.limit {
		r.overflow = true
	}
	return len(body), nil
}

func (g *standaloneUpdateGate) purge() {
	now := g.config.Now()
	for id, transaction := range g.transactions {
		if !transaction.Drained && now.Sub(transaction.Created) > 2*time.Hour {
			delete(g.transactions, id)
		}
	}
}

func (g *standaloneUpdateGate) persist() error {
	body, err := json.Marshal(standaloneUpdateGateDisk{Schema: standaloneUpdateGateSchema, Transactions: g.transactions})
	if err != nil {
		return err
	}
	return atomicfile.Write(g.config.StatePath, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func (g *standaloneUpdateGate) load() error {
	body, err := os.ReadFile(g.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(body) == 0 || len(body) > 256<<10 {
		return errStandaloneUpdateGate
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var disk standaloneUpdateGateDisk
	if decoder.Decode(&disk) != nil || decoder.Decode(&struct{}{}) != io.EOF || disk.Schema != standaloneUpdateGateSchema || len(disk.Transactions) > 128 {
		return errStandaloneUpdateGate
	}
	for id, transaction := range disk.Transactions {
		request := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: id, Version: transaction.Version, ManifestSHA256: transaction.Manifest}
		if request.Validate() != nil || transaction.Target != g.target() || transaction.Target.Validate() != nil || transaction.Created.IsZero() || transaction.Committed && transaction.Drained || transaction.Drained && (!transaction.PolicyBound || transaction.WorkloadGeneration == 0 && transaction.ProtectedWorkloads != 0) || !transaction.Drained && !transaction.Committed && (transaction.WorkloadGeneration != 0 || transaction.ProtectedWorkloads != 0) {
			return errStandaloneUpdateGate
		}
	}
	g.transactions = disk.Transactions
	return nil
}

var _ hostdproto.UpdateGateHandler = (*standaloneUpdateGate)(nil)

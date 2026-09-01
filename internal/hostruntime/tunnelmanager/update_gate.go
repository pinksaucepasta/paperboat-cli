package tunnelmanager

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

var ErrUpdateGateUnavailable = errors.New("tunnel update gate unavailable")

type UpdateGateConfig struct {
	MachineID string
	Manager   *Manager
	HTTP      *http.Client
	StatePath string
}

type UpdateGate struct {
	config             UpdateGateConfig
	operationMu        sync.Mutex
	mu                 sync.Mutex
	drained            map[string]hostdproto.UpdateGateTargetBinding
	transactions       map[string]updateGateTransaction
	recoveryGeneration atomic.Uint64
}

const updateGateStateSchema = "paperboat.update-gate-state/v1"

type updateGateDiskState struct {
	Schema       string                               `json:"schema"`
	Transactions map[string]updateGateDiskTransaction `json:"transactions"`
}

type updateGateDiskTransaction struct {
	Version      string                             `json:"version"`
	Manifest     string                             `json:"manifest_sha256"`
	Path         string                             `json:"path,omitempty"`
	Status       int                                `json:"status,omitempty"`
	Samples      uint16                             `json:"samples,omitempty"`
	Target       hostdproto.UpdateGateTargetBinding `json:"target"`
	Created      time.Time                          `json:"created_at"`
	PolicyBound  bool                               `json:"policy_bound"`
	DrainStarted bool                               `json:"drain_started"`
	Committed    bool                               `json:"committed,omitempty"`
}

type updateGateTransaction struct {
	version, manifest, path string
	status                  int
	samples                 uint16
	target                  hostdproto.UpdateGateTargetBinding
	created                 time.Time
	policyBound             bool
	drainStarted            bool
	committed               bool
}

func NewUpdateGate(config UpdateGateConfig) (*UpdateGate, error) {
	if config.MachineID == "" || config.Manager == nil || !filepath.IsAbs(config.StatePath) {
		return nil, ErrUpdateGateUnavailable
	}
	if config.HTTP == nil {
		config.HTTP = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUpdateGateUnavailable }}
	}
	if err := os.MkdirAll(filepath.Dir(config.StatePath), 0o700); err != nil {
		return nil, err
	}
	gate := &UpdateGate{config: config, drained: make(map[string]hostdproto.UpdateGateTargetBinding), transactions: make(map[string]updateGateTransaction)}
	if err := gate.load(); err != nil {
		return nil, err
	}
	return gate, nil
}

func (g *UpdateGate) HandleUpdateGate(ctx context.Context, request hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error) {
	if g == nil || ctx == nil {
		return hostdproto.UpdateGateResponse{}, ErrUpdateGateUnavailable
	}
	g.operationMu.Lock()
	defer g.operationMu.Unlock()
	g.purgeTransactions(time.Now())
	if request.Validate() != nil {
		return hostdproto.UpdateGateResponse{}, hostdproto.ErrInvalidFrame
	}
	// A committed transaction is retained as a bounded idempotency ledger.
	// Replay must not require the carrier to still have the exact target that
	// completed the transaction, but it must bind to the original signed
	// release and target fence.
	if request.Operation == hostdproto.UpdateGateCommit {
		if existing, ok := g.transactions[request.TransactionID]; ok && existing.committed {
			if !committedTransactionMatches(existing, request) {
				return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
			}
			return hostdproto.UpdateGateResponse{Target: existing.target}, nil
		}
	}
	target, active, routeID, hostname, err := g.current()
	if err != nil {
		return hostdproto.UpdateGateResponse{}, err
	}
	if !matchesUpdateGateTarget(request, target) {
		return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
	}
	switch request.Operation {
	case hostdproto.UpdateGateTarget:
		if existing, ok := g.transactions[request.TransactionID]; ok {
			if existing.version != request.Version || existing.manifest != request.ManifestSHA256 || existing.target != target && (!existing.drainStarted || !sameUpdateWorkload(existing.target, target)) {
				return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
			}
			if existing.target != target {
				existing.target = target
				g.transactions[request.TransactionID] = existing
				g.mu.Lock()
				g.drained[request.TransactionID] = target
				g.mu.Unlock()
			}
			return hostdproto.UpdateGateResponse{Target: target}, nil
		}
		if len(g.transactions) >= 128 {
			return hostdproto.UpdateGateResponse{}, ErrUpdateGateUnavailable
		}
		g.transactions[request.TransactionID] = updateGateTransaction{version: request.Version, manifest: request.ManifestSHA256, target: target, created: time.Now()}
		if err := g.persist(); err != nil {
			delete(g.transactions, request.TransactionID)
			return hostdproto.UpdateGateResponse{}, err
		}
		return hostdproto.UpdateGateResponse{Target: target}, nil
	case hostdproto.UpdateGateCandidate:
		transaction, ok := g.transactions[request.TransactionID]
		if !ok || transaction.committed || transaction.version != request.Version || transaction.manifest != request.ManifestSHA256 || transaction.target != target {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		if transaction.policyBound && (transaction.path != request.Path || transaction.status != request.ExpectedStatus || transaction.samples != request.Samples) {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		transaction.path, transaction.status, transaction.samples, transaction.policyBound = request.Path, request.ExpectedStatus, request.Samples, true
		g.transactions[request.TransactionID] = transaction
		if err := g.persist(); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		if err := g.canary(ctx, target, routeID, hostname, request); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
	case hostdproto.UpdateGateDrain:
		transaction, ok := g.transactions[request.TransactionID]
		if !ok || transaction.committed || !transaction.policyBound || transaction.version != request.Version || transaction.manifest != request.ManifestSHA256 || transaction.target != target {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		transaction.drainStarted = true
		g.transactions[request.TransactionID] = transaction
		g.mu.Lock()
		g.drained[request.TransactionID] = target
		g.mu.Unlock()
		if err := g.persist(); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		if err := active.Drain(ctx); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
	case hostdproto.UpdateGateStability:
		transaction, ok := g.transactions[request.TransactionID]
		if !ok || transaction.committed || !transaction.drainStarted || transaction.version != request.Version || transaction.manifest != request.ManifestSHA256 || transaction.path != request.Path || transaction.status != request.ExpectedStatus || transaction.samples != request.Samples {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		g.mu.Lock()
		_, wasDrained := g.drained[request.TransactionID]
		g.mu.Unlock()
		if wasDrained {
			generation := g.nextRecoveryGeneration()
			if _, replaceErr := g.config.Manager.ReplaceNetworkCarrier(ctx, target.TunnelID, target.ConnectorID, generation); replaceErr != nil {
				return hostdproto.UpdateGateResponse{}, errors.Join(ErrUpdateGateUnavailable, replaceErr)
			}
			target, active, _, _, err = g.current()
			if err != nil || target.TunnelID != request.ExpectedTarget.TunnelID || target.ConnectorID != request.ExpectedTarget.ConnectorID || target.ConfigGeneration != request.ExpectedTarget.ConfigGeneration || active == nil {
				return hostdproto.UpdateGateResponse{}, errors.Join(ErrGenerationConflict, err)
			}
			transaction.target = target
			g.transactions[request.TransactionID] = transaction
			g.mu.Lock()
			g.drained[request.TransactionID] = target
			g.mu.Unlock()
			if err := g.persist(); err != nil {
				return hostdproto.UpdateGateResponse{}, err
			}
		}
		deadline := time.Now().Add(time.Duration(request.WindowMillis) * time.Millisecond)
		for {
			current, _, currentRoute, currentHost, currentErr := g.current()
			if currentErr != nil || current != target {
				return hostdproto.UpdateGateResponse{}, errors.Join(ErrUpdateGateUnavailable, currentErr)
			}
			canaryRequest := request
			canaryRequest.Operation = hostdproto.UpdateGateCandidate
			canaryRequest.Path, canaryRequest.ExpectedStatus, canaryRequest.Samples = request.Path, request.ExpectedStatus, request.Samples
			canaryRequest.TimeoutMillis = request.IntervalMillis
			canaryRequest.WindowMillis, canaryRequest.IntervalMillis = 0, 0
			if err := g.canary(ctx, current, currentRoute, currentHost, canaryRequest); err != nil {
				return hostdproto.UpdateGateResponse{}, err
			}
			if !time.Now().Before(deadline) {
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
		transaction, transactionOK := g.transactions[request.TransactionID]
		if !transactionOK || transaction.committed || !transaction.drainStarted || transaction.version != request.Version || transaction.manifest != request.ManifestSHA256 || transaction.path != request.Path || transaction.status != request.ExpectedStatus || transaction.samples != request.Samples || transaction.target != target {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		g.mu.Lock()
		expected, ok := g.drained[request.TransactionID]
		g.mu.Unlock()
		if !ok || expected != target {
			return hostdproto.UpdateGateResponse{}, ErrUpdateGateUnavailable
		}
		generation := g.nextRecoveryGeneration()
		restored, replaceErr := g.config.Manager.ReplaceNetworkCarrier(ctx, target.TunnelID, target.ConnectorID, generation)
		if replaceErr != nil || restored == nil {
			return hostdproto.UpdateGateResponse{}, errors.Join(ErrUpdateGateUnavailable, replaceErr)
		}
		newTarget, _, newRoute, newHost, currentErr := g.current()
		if currentErr != nil || newTarget.TunnelID != target.TunnelID || newTarget.ConnectorID != target.ConnectorID || newTarget.ConfigGeneration != target.ConfigGeneration {
			return hostdproto.UpdateGateResponse{}, errors.Join(ErrUpdateGateUnavailable, currentErr)
		}
		probe := request
		probe.Operation = hostdproto.UpdateGateCandidate
		if err := g.canary(ctx, newTarget, newRoute, newHost, probe); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		g.mu.Lock()
		delete(g.drained, request.TransactionID)
		g.mu.Unlock()
		delete(g.transactions, request.TransactionID)
		if err := g.persist(); err != nil {
			return hostdproto.UpdateGateResponse{}, err
		}
		target = newTarget
	case hostdproto.UpdateGateCommit:
		transaction, ok := g.transactions[request.TransactionID]
		if !ok || transaction.committed || !transaction.policyBound || !transaction.drainStarted || transaction.version != request.Version || transaction.manifest != request.ManifestSHA256 || transaction.target != target {
			return hostdproto.UpdateGateResponse{}, ErrGenerationConflict
		}
		g.mu.Lock()
		expected, drained := g.drained[request.TransactionID]
		g.mu.Unlock()
		if !drained || expected != target {
			return hostdproto.UpdateGateResponse{}, ErrUpdateGateUnavailable
		}
		previous := transaction
		transaction.committed = true
		transaction.drainStarted = false
		g.transactions[request.TransactionID] = transaction
		g.mu.Lock()
		delete(g.drained, request.TransactionID)
		g.mu.Unlock()
		if err := g.persist(); err != nil {
			g.transactions[request.TransactionID] = previous
			g.mu.Lock()
			g.drained[request.TransactionID] = expected
			g.mu.Unlock()
			return hostdproto.UpdateGateResponse{}, err
		}
	default:
		return hostdproto.UpdateGateResponse{}, ErrUpdateGateUnavailable
	}
	return hostdproto.UpdateGateResponse{Target: target}, nil
}

func committedTransactionMatches(transaction updateGateTransaction, request hostdproto.UpdateGateRequest) bool {
	return transaction.committed && transaction.version == request.Version && transaction.manifest == request.ManifestSHA256 && request.ExpectedTarget != nil && *request.ExpectedTarget == transaction.target
}

func sameUpdateWorkload(a, b hostdproto.UpdateGateTargetBinding) bool {
	return a.MachineID == b.MachineID && a.AccountID == b.AccountID && a.HostID == b.HostID && a.TunnelID == b.TunnelID && a.ConnectorID == b.ConnectorID && a.ConfigGeneration == b.ConfigGeneration && a.RouteGeneration == b.RouteGeneration
}

func (g *UpdateGate) purgeTransactions(now time.Time) {
	for id, transaction := range g.transactions {
		if !transaction.drainStarted && now.Sub(transaction.created) > 2*time.Hour {
			delete(g.transactions, id)
			g.mu.Lock()
			delete(g.drained, id)
			g.mu.Unlock()
		}
	}
}

func (g *UpdateGate) persist() error {
	disk := updateGateDiskState{Schema: updateGateStateSchema, Transactions: make(map[string]updateGateDiskTransaction, len(g.transactions))}
	for id, value := range g.transactions {
		disk.Transactions[id] = updateGateDiskTransaction{Version: value.version, Manifest: value.manifest, Path: value.path, Status: value.status, Samples: value.samples, Target: value.target, Created: value.created, PolicyBound: value.policyBound, DrainStarted: value.drainStarted, Committed: value.committed}
	}
	body, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	return atomicfile.Write(g.config.StatePath, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func (g *UpdateGate) load() error {
	body, err := os.ReadFile(g.config.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(body) == 0 || len(body) > 256<<10 {
		return ErrUpdateGateUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var disk updateGateDiskState
	if decoder.Decode(&disk) != nil || decoder.Decode(&struct{}{}) != io.EOF || disk.Schema != updateGateStateSchema || len(disk.Transactions) > 128 {
		return ErrUpdateGateUnavailable
	}
	for id, value := range disk.Transactions {
		if id == "" || value.Created.IsZero() || value.Target.MachineID != g.config.MachineID || value.Target.Validate() != nil {
			return ErrUpdateGateUnavailable
		}
		base := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: id, Version: value.Version, ManifestSHA256: value.Manifest}
		if base.Validate() != nil {
			return ErrUpdateGateUnavailable
		}
		if value.PolicyBound {
			policy := hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateCandidate, TransactionID: id, Version: value.Version, ManifestSHA256: value.Manifest, Path: value.Path, ExpectedStatus: value.Status, Samples: value.Samples, TimeoutMillis: 1, ExpectedTarget: &value.Target}
			if policy.Validate() != nil {
				return ErrUpdateGateUnavailable
			}
		} else if value.Path != "" || value.Status != 0 || value.Samples != 0 {
			return ErrUpdateGateUnavailable
		}
		if value.DrainStarted && !value.PolicyBound || value.Committed && (!value.PolicyBound || value.DrainStarted) {
			return ErrUpdateGateUnavailable
		}
		transaction := updateGateTransaction{version: value.Version, manifest: value.Manifest, path: value.Path, status: value.Status, samples: value.Samples, target: value.Target, created: value.Created, policyBound: value.PolicyBound, drainStarted: value.DrainStarted, committed: value.Committed}
		g.transactions[id] = transaction
		if transaction.drainStarted && !transaction.committed {
			g.drained[id] = transaction.target
		}
	}
	return nil
}

func matchesUpdateGateTarget(request hostdproto.UpdateGateRequest, current hostdproto.UpdateGateTargetBinding) bool {
	return request.Operation == hostdproto.UpdateGateTarget && request.ExpectedTarget == nil || request.Operation != hostdproto.UpdateGateTarget && request.ExpectedTarget != nil && *request.ExpectedTarget == current
}

func (g *UpdateGate) nextRecoveryGeneration() uint64 {
	current := g.config.Manager.NetworkGeneration()
	for {
		seen := g.recoveryGeneration.Load()
		if seen < current {
			g.recoveryGeneration.CompareAndSwap(seen, current)
			continue
		}
		return g.recoveryGeneration.Add(1)
	}
}

func (g *UpdateGate) current() (hostdproto.UpdateGateTargetBinding, Active, string, string, error) {
	values := g.config.Manager.ActiveSnapshot()
	if len(values) == 0 {
		return hostdproto.UpdateGateTargetBinding{}, nil, "", "", ErrUpdateGateUnavailable
	}
	keys := sortedActiveKeys(values)
	var active Active
	var identity connector.DataCarrierIdentity
	var info connector.DataCarrierInfo
	var routeID, hostname string
	var routeGeneration uint64
	for _, key := range keys {
		candidate := values[key]
		provider, ok := candidate.(ActiveCarrierProvider)
		if !ok || provider.ActiveDataCarrier() == nil {
			continue
		}
		candidateIdentity, identityOK := provider.ActiveDataCarrier().Identity()
		candidateInfo, infoOK := readyCarrierInfo(provider.ActiveDataCarrier().Snapshot())
		routeSource, routeOK := candidate.(interface {
			updateGateRoute() (string, string, uint64, bool)
		})
		if !identityOK || !infoOK || !routeOK {
			continue
		}
		candidateRoute, candidateHost, candidateGeneration, candidateRouteOK := routeSource.updateGateRoute()
		if !candidateRouteOK {
			continue
		}
		active, identity, info, routeID, hostname, routeGeneration = candidate, candidateIdentity, candidateInfo, candidateRoute, candidateHost, candidateGeneration
		break
	}
	if active == nil {
		return hostdproto.UpdateGateTargetBinding{}, nil, "", "", ErrUpdateGateUnavailable
	}
	if identity.SessionGeneration == 0 {
		return hostdproto.UpdateGateTargetBinding{}, nil, "", "", ErrUpdateGateUnavailable
	}
	target := hostdproto.UpdateGateTargetBinding{MachineID: g.config.MachineID, AccountID: identity.AccountID, HostID: identity.HostID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, EdgeNodeID: info.EdgeID, ProcessEpoch: identity.ProcessGeneration, SessionGeneration: identity.SessionGeneration, ConfigGeneration: identity.Generation, RouteGeneration: routeGeneration, FailureDomain: info.FailureDomain}
	return target, active, routeID, hostname, nil
}

func sortedActiveKeys(values map[string]Active) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func readyCarrierInfo(values []connector.DataCarrierInfo) (connector.DataCarrierInfo, bool) {
	for _, value := range values {
		if value.State == connector.DataCarrierReady && value.EdgeID != "" && value.FailureDomain != "" {
			return value, true
		}
	}
	return connector.DataCarrierInfo{}, false
}

func (g *UpdateGate) canary(ctx context.Context, target hostdproto.UpdateGateTargetBinding, routeID, hostname string, request hostdproto.UpdateGateRequest) error {
	parsed, err := url.Parse("https://" + hostname + request.Path)
	if err != nil || parsed.Hostname() != hostname || parsed.User != nil || routeID == "" {
		return ErrUpdateGateUnavailable
	}
	for range request.Samples {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Paperboat-Update-Canary", request.TransactionID)
		response, err := g.config.HTTP.Do(req)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(io.Discard, response.Body, 64<<10)
		closeErr := response.Body.Close()
		if copyErr != nil && !errors.Is(copyErr, io.EOF) || closeErr != nil || response.StatusCode != request.ExpectedStatus {
			return ErrUpdateGateUnavailable
		}
		current, _, currentRoute, _, currentErr := g.current()
		if currentErr != nil || current != target || currentRoute != routeID {
			return ErrUpdateGateUnavailable
		}
	}
	return nil
}

var _ hostdproto.UpdateGateHandler = (*UpdateGate)(nil)

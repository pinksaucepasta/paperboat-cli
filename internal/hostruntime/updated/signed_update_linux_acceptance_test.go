//go:build linux && trk28_remote_acceptance

package updated_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
	updatedruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/updated"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

// TestLinuxSignedUpdateAcceptance is deliberately opt-in and build-tagged.
// It exercises the production TUF source with a real signed target, while all
// edge/hostd endpoints remain an isolated local edge canary fixture. No
// process, service manager, or local Docker/Postgres state is used.
func TestLinuxSignedUpdateAcceptance(t *testing.T) {
	repositoryURL := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_TUF_REPOSITORY_URL"))
	if repositoryURL == "" {
		t.Skip("PAPERBOAT_TEST_TUF_REPOSITORY_URL is not set")
	}
	expectedVersion := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_TUF_VERSION"))
	if expectedVersion == "" {
		t.Fatal("PAPERBOAT_TEST_TUF_VERSION is not set")
	}
	var repositoryHTTP *http.Client
	localRepositoryRoot := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK28_LOCAL_TUF_ROOT"))
	if localRepositoryRoot != "" {
		if !filepath.IsAbs(localRepositoryRoot) || filepath.Clean(localRepositoryRoot) != localRepositoryRoot {
			t.Fatalf("PAPERBOAT_TRK28_LOCAL_TUF_ROOT must be an absolute clean path, got %q", localRepositoryRoot)
		}
		for _, name := range []string{"metadata", "targets"} {
			info, statErr := os.Stat(filepath.Join(localRepositoryRoot, name))
			if statErr != nil || !info.IsDir() {
				t.Fatalf("local TUF repository %s is unavailable", filepath.Join(localRepositoryRoot, name))
			}
		}
		// Keep the generated repository private to this acceptance process. The
		// test client trusts only this server's ephemeral certificate, and the
		// listener is bound by httptest to loopback.
		repositoryServer := httptest.NewTLSServer(http.FileServer(http.Dir(localRepositoryRoot)))
		t.Cleanup(repositoryServer.Close)
		rootCAs, poolErr := x509.SystemCertPool()
		if poolErr != nil {
			rootCAs = x509.NewCertPool()
		}
		rootCAs.AddCert(repositoryServer.Certificate())
		repositoryURL = repositoryServer.URL
		repositoryHTTP = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs}}}
	}
	machineID := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK28_MACHINE_ID"))
	if machineID == "" {
		machineID = "mch_trk28_acceptance"
	}
	failureDomain := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK28_FAILURE_DOMAIN"))
	if failureDomain == "" {
		t.Fatal("PAPERBOAT_TRK28_FAILURE_DOMAIN is not set; do not guess the signed cohort domain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	root := t.TempDir()
	for _, name := range []string{"index", "targets"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := workerupdate.TUFSource{
		RepositoryURL: repositoryURL,
		StateRoot:     root,
		HTTP:          repositoryHTTP,
		MachineID:     machineID,
		FailureDomain: workerupdate.FailureDomainSourceFunc(func(_ context.Context, request workerupdate.FailureDomainRequest) (string, error) {
			if request.MachineID != machineID || request.Version != expectedVersion {
				return "", workerupdate.ErrFailureDomainUnavailable
			}
			return failureDomain, nil
		}),
		Deferral: workerupdate.DeferralSourceFunc(func(context.Context) (releasepolicy.Deferral, bool, error) {
			return releasepolicy.Deferral{}, false, nil
		}),
	}
	candidate, found, err := source.ResolveManual(ctx)
	if err != nil {
		t.Fatalf("resolve signed candidate: %v", err)
	}
	if !found {
		t.Fatalf("signed release %s was not eligible", expectedVersion)
	}
	if candidate.Version != expectedVersion {
		t.Fatalf("signed candidate version=%q, want %q", candidate.Version, expectedVersion)
	}
	if err := workerupdate.ValidateActivationRelease(candidate); err != nil {
		t.Fatalf("signed candidate activation policy: %v", err)
	}
	t.Logf("signed candidate version=%s sha256=%s length=%d canary=%s status=%d samples=%d stability=%s interval=%s", candidate.Version, candidate.SHA256, candidate.Length, candidate.CanaryPath, candidate.CanaryStatus, candidate.CanarySamples, candidate.StabilityWindow, candidate.StabilityInterval)

	active, err := syntheticPreviousRelease(candidate)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("commit_with_local_edge_canary", func(t *testing.T) {
		fixture := newSignedAcceptanceFixture(t, source, active, candidate, false)
		result, err := fixture.manager.Activate(ctx, candidate)
		if err != nil {
			t.Fatalf("signed update activation: %v", err)
		}
		if !result.Updated || result.Version != candidate.Version {
			t.Fatalf("activation result=%+v", result)
		}
		if got := fixture.hostd.currentVersion(); got != candidate.Version {
			t.Fatalf("hostd active version=%q, want %q", got, candidate.Version)
		}
		if got := fixture.edge.currentVersion(); got != candidate.Version {
			t.Fatalf("edge active version=%q, want %q", got, candidate.Version)
		}
		if !fixture.edge.drainedAtLeastOnce() {
			t.Fatal("edge was not drained before activation")
		}
		if fixture.edge.commitCount() != 1 {
			t.Fatalf("edge commit count=%d, want 1", fixture.edge.commitCount())
		}
		phases := fixture.events.phasesSnapshot()
		for _, want := range []workerupdate.EventPhase{workerupdate.EventCandidateValidating, workerupdate.EventDraining, workerupdate.EventCommitted} {
			if !containsPhase(phases, want) {
				t.Fatalf("events=%v missing %q", phases, want)
			}
		}
		journal, err := updateflow.Load(fixture.journal)
		if err != nil {
			t.Fatal(err)
		}
		if journal.Stage != updateflow.StageIdle || journal.ActiveVersion != candidate.Version {
			t.Fatalf("committed journal=%+v", journal)
		}
		t.Logf("commit evidence: edge_canary_probes=%d stability_probes=%d drained=%t active=%s journal=%s", fixture.edge.canaryProbes(), fixture.edge.stabilityProbes(), fixture.edge.drainedAtLeastOnce(), journal.ActiveVersion, journal.Stage)
	})

	t.Run("health_failure_rolls_back_and_quarantines", func(t *testing.T) {
		fixture := newSignedAcceptanceFixture(t, source, active, candidate, true)
		_, err := fixture.manager.Activate(ctx, candidate)
		if err == nil || !strings.Contains(err.Error(), "injected edge health failure") {
			t.Fatalf("failure activation error=%v", err)
		}
		if got := fixture.hostd.currentVersion(); got != active.Version {
			t.Fatalf("hostd rollback version=%q, want %q", got, active.Version)
		}
		if got := fixture.edge.currentVersion(); got != active.Version {
			t.Fatalf("edge rollback version=%q, want %q", got, active.Version)
		}
		if fixture.edge.isDrained() {
			t.Fatal("edge remained drained after rollback")
		}
		phases := fixture.events.phasesSnapshot()
		for _, want := range []workerupdate.EventPhase{workerupdate.EventRolledBack, workerupdate.EventQuarantined} {
			if !containsPhase(phases, want) {
				t.Fatalf("events=%v missing %q", phases, want)
			}
		}
		journal, err := updateflow.Load(fixture.journal)
		if err != nil {
			t.Fatal(err)
		}
		if journal.Stage != updateflow.StageIdle || journal.LastFailure != updateflow.FailureHealth || journal.CandidateVersion != candidate.Version {
			t.Fatalf("rollback journal=%+v", journal)
		}
		t.Logf("rollback evidence: edge_rollback_probes=%d active=%s quarantined=%s journal_failure=%s", fixture.edge.rollbackProbes(), journal.ActiveVersion, journal.CandidateVersion, journal.LastFailure)
	})
}

type signedAcceptanceFixture struct {
	manager *workerupdate.Manager
	hostd   *signedAcceptanceHostd
	edge    *signedAcceptanceEdge
	events  *signedAcceptanceEvents
	journal string
}

func newSignedAcceptanceFixture(t *testing.T, source workerupdate.TUFSource, active, candidate workerupdate.Release, failHealth bool) signedAcceptanceFixture {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"current", "rollback", "staged", "state"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current", "pb")
	rollback := filepath.Join(root, "rollback", "pb")
	staged := filepath.Join(root, "staged", "pb")
	journal := filepath.Join(root, "state", "transaction.json")
	if err := os.WriteFile(current, body, 0o700); err != nil {
		t.Fatal(err)
	}
	edge := newSignedAcceptanceEdge(candidate)
	t.Cleanup(edge.Close)
	hostd := newSignedAcceptanceHostd(active, edge)
	starter := &signedAcceptanceStarter{hostd: hostd, edge: edge}
	events := &signedAcceptanceEvents{}
	provider := &signedAcceptanceDeploymentProvider{edge: edge, target: signedAcceptanceTarget()}
	gate, err := workerupdate.NewDeploymentActivationGate(workerupdate.DeploymentActivationGateConfig{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	health := &signedAcceptanceHealth{edge: edge, fail: failHealth, http: updatedruntime.HTTPHealth{Endpoint: edge.URL()}}
	manager, err := workerupdate.New(workerupdate.Config{
		StatePath: journal, Binary: current, BinaryRollback: rollback, BinaryStaged: staged,
		Active: active, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), WorkerUID: os.Geteuid(), WorkerGID: os.Getegid(),
		HostdEndpoint: "local-signed-acceptance", Capability: bytes.Repeat([]byte{0xa5}, 32), Fetcher: source,
		Starter: starter, Hostd: hostd, Health: health, Gate: gate, Events: events,
		MonitorWindow: time.Second, HealthInterval: time.Millisecond, CanaryTimeout: 30 * time.Second,
		DrainTimeout: 2 * time.Minute, RollbackTimeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signedAcceptanceFixture{manager: manager, hostd: hostd, edge: edge, events: events, journal: journal}
}

func syntheticPreviousRelease(candidate workerupdate.Release) (workerupdate.Release, error) {
	version, err := previousVersion(candidate.Version)
	if err != nil {
		return workerupdate.Release{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return workerupdate.Release{}, err
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		return workerupdate.Release{}, err
	}
	digest := sha256.Sum256(body)
	active := candidate
	active.Version = version
	active.SHA256 = hex.EncodeToString(digest[:])
	active.Length = int64(len(body))
	active.CLISHA256 = active.SHA256
	active.CLILength = active.Length
	active.CLISHA256 = active.SHA256
	return active, nil
}

func previousVersion(value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid signed version %q", value)
	}
	last, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return "", err
	}
	if last > 0 {
		parts[3] = strconv.FormatUint(last-1, 10)
		return strings.Join(parts, "."), nil
	}
	date, err := time.Parse("2006.01.02", strings.Join(parts[:3], "."))
	if err != nil {
		return "", err
	}
	date = date.Add(-24 * time.Hour)
	return fmt.Sprintf("%04d.%02d.%02d.999999", date.Year(), date.Month(), date.Day()), nil
}

type signedAcceptanceEdge struct {
	server         *httptest.Server
	mu             sync.Mutex
	active         string
	candidate      string
	canaryStatus   int
	candidateReady bool
	drained        bool
	drainCount     int
	canaryCount    int
	stabilityCount int
	rollbackCount  int
	commitTotal    int
}

func newSignedAcceptanceEdge(candidate workerupdate.Release) *signedAcceptanceEdge {
	edge := &signedAcceptanceEdge{candidate: candidate.Version, canaryStatus: candidate.CanaryStatus, active: "pending"}
	edge.server = httptest.NewServer(http.HandlerFunc(edge.serveHTTP))
	return edge
}

func (e *signedAcceptanceEdge) URL() string { return e.server.URL + "/healthz" }

func (e *signedAcceptanceEdge) Close() {
	if e != nil && e.server != nil {
		e.server.Close()
	}
}

func (e *signedAcceptanceEdge) serveHTTP(w http.ResponseWriter, request *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if request.URL.Path == "/healthz" && request.Header.Get("X-Paperboat-Update-Candidate") == "" {
		w.Header().Set("X-Paperboat-Release-Version", e.active)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"live":true}`)
		return
	}
	if e.drained {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	version := e.active
	if candidate := request.Header.Get("X-Paperboat-Update-Candidate"); candidate != "" {
		if !e.candidateReady || candidate != e.candidate {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		version = candidate
	}
	w.Header().Set("X-Paperboat-Release-Version", version)
	w.WriteHeader(e.canaryStatus)
}

func (e *signedAcceptanceEdge) prepareCandidate() {
	e.mu.Lock()
	e.candidateReady = true
	e.mu.Unlock()
}

func (e *signedAcceptanceEdge) activate(version string) {
	e.mu.Lock()
	e.active = version
	e.candidateReady = false
	e.drained = false
	e.mu.Unlock()
}

func (e *signedAcceptanceEdge) drain() {
	e.mu.Lock()
	e.drained = true
	e.drainCount++
	e.mu.Unlock()
}

func (e *signedAcceptanceEdge) isDrained() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.drained
}

func (e *signedAcceptanceEdge) currentVersion() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active
}

func (e *signedAcceptanceEdge) drainedAtLeastOnce() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.drainCount > 0
}

func (e *signedAcceptanceEdge) canaryProbes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.canaryCount
}

func (e *signedAcceptanceEdge) stabilityProbes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stabilityCount
}

func (e *signedAcceptanceEdge) rollbackProbes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rollbackCount
}

func (e *signedAcceptanceEdge) commitCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.commitTotal
}

func (e *signedAcceptanceEdge) request(ctx context.Context, path, expectedVersion string, expectedStatus int, candidate bool) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.server.URL+path, nil)
	if err != nil {
		return err
	}
	if candidate {
		request.Header.Set("X-Paperboat-Update-Candidate", expectedVersion)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("edge status=%d want=%d", response.StatusCode, expectedStatus)
	}
	if expectedStatus >= 200 && expectedStatus < 300 && response.Header.Get("X-Paperboat-Release-Version") != expectedVersion {
		return fmt.Errorf("edge version=%q want=%q", response.Header.Get("X-Paperboat-Release-Version"), expectedVersion)
	}
	return nil
}

type signedAcceptanceHostd struct {
	mu     sync.Mutex
	status hostdproto.Status
	edge   *signedAcceptanceEdge
}

func newSignedAcceptanceHostd(active workerupdate.Release, edge *signedAcceptanceEdge) *signedAcceptanceHostd {
	edge.activate(active.Version)
	return &signedAcceptanceHostd{status: hostdproto.Status{State: hostdproto.StateActive, WorkerID: "runtime-" + active.Version, APIVersion: active.HostdAPIMin, Epoch: 1, LastHeartbeatUnixMilli: time.Now().UnixMilli()}, edge: edge}
}

func (h *signedAcceptanceHostd) Active(context.Context) (hostdproto.Status, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.LastHeartbeatUnixMilli = time.Now().UnixMilli()
	return h.status, nil
}

func (h *signedAcceptanceHostd) activate(version string, epoch uint64, api uint16) {
	h.mu.Lock()
	h.status = hostdproto.Status{State: hostdproto.StateActive, WorkerID: "runtime-" + version, APIVersion: api, Epoch: epoch, LastHeartbeatUnixMilli: time.Now().UnixMilli()}
	h.mu.Unlock()
	h.edge.activate(version)
}

func (h *signedAcceptanceHostd) currentVersion() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.TrimPrefix(h.status.WorkerID, "runtime-")
}

type signedAcceptanceStarter struct {
	hostd *signedAcceptanceHostd
	edge  *signedAcceptanceEdge
}

func (s *signedAcceptanceStarter) Start(_ context.Context, request workerupdate.StartRequest) (workerupdate.Worker, error) {
	return &signedAcceptanceWorker{starter: s, request: request}, nil
}

type signedAcceptanceWorker struct {
	starter *signedAcceptanceStarter
	request workerupdate.StartRequest
	epoch   uint64
}

func (w *signedAcceptanceWorker) Ready(ctx context.Context) (hostdproto.Status, error) {
	status, err := w.starter.hostd.Active(ctx)
	if err != nil {
		return hostdproto.Status{}, err
	}
	w.epoch = status.Epoch + 1
	if w.request.Release.Version == w.starter.edge.candidate {
		w.starter.edge.prepareCandidate()
	}
	return hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: w.request.WorkerID, APIVersion: w.request.Release.HostdAPIMin, Epoch: w.epoch}, nil
}

func (w *signedAcceptanceWorker) Activate(context.Context) (hostdproto.Status, error) {
	w.starter.hostd.activate(w.request.Release.Version, w.epoch, w.request.Release.HostdAPIMin)
	return w.starter.hostd.Active(context.Background())
}

func (*signedAcceptanceWorker) Stop(context.Context) error { return nil }

type signedAcceptanceDeploymentProvider struct {
	edge   *signedAcceptanceEdge
	target workerupdate.DeploymentTarget
}

func signedAcceptanceTarget() workerupdate.DeploymentTarget {
	return workerupdate.DeploymentTarget{Scope: hostdproto.UpdateGateScopeTunnel, MachineID: "mch_trk28_acceptance", AccountID: "acct_trk28", HostID: "host_trk28", TunnelID: "tunnel_trk28", ConnectorID: "connector_trk28", EdgeNodeID: "edge_trk28", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "hetzner_edge"}
}

func (p *signedAcceptanceDeploymentProvider) CurrentTarget(context.Context, workerupdate.TargetRequest) (workerupdate.DeploymentTarget, error) {
	return p.target, nil
}

func (p *signedAcceptanceDeploymentProvider) ProbeCandidate(ctx context.Context, request workerupdate.CanaryProbeRequest) error {
	if request.Version != p.edge.candidate || request.Target != p.target || !request.RequireEdge || !request.RequireConnector || !request.RequireRoute || !request.RequireOrigin {
		return errors.New("signed candidate target fence mismatch")
	}
	if err := p.edge.request(ctx, request.Path, request.Version, request.ExpectedStatus, true); err != nil {
		return err
	}
	p.edge.mu.Lock()
	p.edge.canaryCount++
	p.edge.mu.Unlock()
	return nil
}

func (p *signedAcceptanceDeploymentProvider) Drain(ctx context.Context, request workerupdate.DrainRequest) error {
	if request.Target != p.target {
		return errors.New("signed drain target fence mismatch")
	}
	p.edge.drain()
	if err := p.edge.request(ctx, "/drain-check", request.Previous, http.StatusServiceUnavailable, false); err != nil {
		return err
	}
	return nil
}

func (p *signedAcceptanceDeploymentProvider) ObserveStability(ctx context.Context, request workerupdate.StabilityRequest) error {
	if request.Target != p.target || request.Candidate != p.edge.candidate {
		return errors.New("signed stability target fence mismatch")
	}
	for sample := uint16(0); sample < request.Samples; sample++ {
		if err := p.edge.request(ctx, request.Path, request.Candidate, request.ExpectedStatus, false); err != nil {
			return err
		}
		p.edge.mu.Lock()
		p.edge.stabilityCount++
		p.edge.mu.Unlock()
	}
	return nil
}

func (p *signedAcceptanceDeploymentProvider) VerifyRollback(ctx context.Context, request workerupdate.RollbackRequest) error {
	if request.Target != p.target || request.Restore == "" {
		return errors.New("signed rollback target fence mismatch")
	}
	if err := p.edge.request(ctx, "/rollback-check", request.Restore, request.ExpectedStatus, false); err != nil {
		return err
	}
	p.edge.mu.Lock()
	p.edge.rollbackCount++
	p.edge.mu.Unlock()
	return nil
}

func (p *signedAcceptanceDeploymentProvider) Commit(_ context.Context, request workerupdate.CommitRequest) error {
	if request.Version != p.edge.candidate || request.ManifestSHA256 == "" || request.Target != p.target || p.edge.currentVersion() != p.edge.candidate || p.edge.isDrained() {
		return errors.New("signed commit target fence mismatch")
	}
	p.edge.mu.Lock()
	p.edge.commitTotal++
	p.edge.mu.Unlock()
	return nil
}

type signedAcceptanceHealth struct {
	edge *signedAcceptanceEdge
	http updatedruntime.HTTPHealth
	fail bool
}

func (h *signedAcceptanceHealth) Check(ctx context.Context, status hostdproto.Status, release workerupdate.Release) error {
	if h.fail {
		return errors.New("injected edge health failure")
	}
	if err := h.http.Check(ctx, status, release); err != nil {
		return err
	}
	if h.edge.currentVersion() != release.Version || h.edge.isDrained() {
		return errors.New("edge health route is not active")
	}
	return nil
}

type signedAcceptanceEvents struct {
	mu     sync.Mutex
	phases []workerupdate.EventPhase
}

func (e *signedAcceptanceEvents) RecordUpdateEvent(_ context.Context, event workerupdate.Event) error {
	e.mu.Lock()
	e.phases = append(e.phases, event.Phase)
	e.mu.Unlock()
	return nil
}

func (e *signedAcceptanceEvents) phasesSnapshot() []workerupdate.EventPhase {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]workerupdate.EventPhase(nil), e.phases...)
}

func containsPhase(phases []workerupdate.EventPhase, want workerupdate.EventPhase) bool {
	for _, phase := range phases {
		if phase == want {
			return true
		}
	}
	return false
}

var _ workerupdate.Fetcher = workerupdate.TUFSource{}
var _ workerupdate.Starter = (*signedAcceptanceStarter)(nil)
var _ workerupdate.Hostd = (*signedAcceptanceHostd)(nil)
var _ workerupdate.HealthChecker = (*signedAcceptanceHealth)(nil)
var _ workerupdate.SignedDeploymentProvider = (*signedAcceptanceDeploymentProvider)(nil)
var _ workerupdate.EventSink = (*signedAcceptanceEvents)(nil)

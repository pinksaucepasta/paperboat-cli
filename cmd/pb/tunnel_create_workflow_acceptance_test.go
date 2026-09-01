package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelcreatejournal"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/spf13/cobra"
)

const workflowAcceptanceSecret = "workflow-secret-canary-18f7"

type workflowAcceptanceEvents struct {
	mu     sync.Mutex
	values []string
}

func (e *workflowAcceptanceEvents) add(value string) {
	e.mu.Lock()
	e.values = append(e.values, value)
	e.mu.Unlock()
}

func (e *workflowAcceptanceEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.values...)
}

type workflowAcceptanceEnrollment struct {
	harness *workflowAcceptanceHarness
	fail    error
}

func (e *workflowAcceptanceEnrollment) Enroll(ctx context.Context, tunnelID, requestID string) (tunnelenrollment.Projection, error) {
	if e.harness.event("hostd.connector.enroll") {
		return tunnelenrollment.Projection{}, ctx.Err()
	}
	if tunnelID != "tun_workflow" || !strings.HasPrefix(requestID, "connector-add-") {
		return tunnelenrollment.Projection{}, tunnelenrollment.ErrInvalid
	}
	if e.fail != nil {
		err := e.fail
		e.fail = nil
		return tunnelenrollment.Projection{}, err
	}
	if e.harness.event("hostd.connector.activate") {
		return tunnelenrollment.Projection{}, ctx.Err()
	}
	e.harness.events.add("hostd.connector.ready")
	ready := time.Unix(30, 0).UTC()
	return tunnelenrollment.Projection{
		Schema: tunnelenrollment.Schema, Kind: "tunnel_connector", TunnelID: tunnelID,
		HostID: "host_workflow", ConnectorID: "connector_workflow", OperationID: "operation_connector_workflow",
		State: "ready", CredentialReference: "protected-file://paperboat/" + workflowAcceptanceSecret,
		CredentialGeneration: 1, ReadyAt: &ready,
	}, nil
}

type recordingTunnelCreateWorkflow struct {
	harness *workflowAcceptanceHarness
	session *tunnelcreatejournal.Session
}

func (w *recordingTunnelCreateWorkflow) Snapshot() tunnelcreatejournal.Journal {
	return w.session.Snapshot()
}

func (w *recordingTunnelCreateWorkflow) RecordTunnel(ctx context.Context, tunnelID, operationID string) error {
	if w.harness.event("workflow.tunnel") {
		return ctx.Err()
	}
	return w.session.RecordTunnel(ctx, tunnelID, operationID)
}

func (w *recordingTunnelCreateWorkflow) RecordConnectorReady(ctx context.Context) error {
	if w.harness.event("workflow.connector") {
		return ctx.Err()
	}
	return w.session.RecordConnectorReady(ctx)
}

func (w *recordingTunnelCreateWorkflow) RecordDomain(ctx context.Context, index int, domainID string) error {
	if w.harness.event("workflow.domain") {
		return ctx.Err()
	}
	return w.session.RecordDomain(ctx, index, domainID)
}

func (w *recordingTunnelCreateWorkflow) Complete(ctx context.Context) error {
	if w.harness.event("workflow.complete") {
		return ctx.Err()
	}
	return w.session.Complete(ctx)
}

func (w *recordingTunnelCreateWorkflow) Close() error {
	w.harness.events.add("workflow.close")
	return w.session.Close()
}

type workflowAcceptanceWriter struct {
	harness *workflowAcceptanceHarness
	buffer  bytes.Buffer
	wrote   bool
}

func (w *workflowAcceptanceWriter) Write(body []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		if w.harness.event("output") {
			return 0, w.harness.commandContext.Err()
		}
	}
	return w.buffer.Write(body)
}

type workflowAcceptanceHarness struct {
	t              *testing.T
	events         workflowAcceptanceEvents
	stateRoot      string
	server         *httptest.Server
	ready          bool
	keySequence    int
	createCalls    int
	domainCalls    int
	cancelAt       string
	cancel         context.CancelFunc
	commandContext context.Context
	lastRequest    tunnelCreateWorkflowRequest
	hasRequest     bool
	enrollment     *workflowAcceptanceEnrollment
}

func newWorkflowAcceptanceHarness(t *testing.T) *workflowAcceptanceHarness {
	t.Helper()
	h := &workflowAcceptanceHarness{t: t, stateRoot: t.TempDir()}
	h.enrollment = &workflowAcceptanceEnrollment{harness: h}
	h.server = httptest.NewServer(http.HandlerFunc(h.serveControlPlane))
	t.Cleanup(h.server.Close)

	oldClient := tunnelClientForCommand
	oldWorkflow := beginTunnelCreateWorkflowForCommand
	oldKey := newTunnelIdempotencyKey
	oldRuntime := tunnelConnectorAddRuntime
	oldEnrollment := connectorEnrollmentLocalClient
	oldProbe, oldRepair := tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	t.Cleanup(func() {
		tunnelClientForCommand = oldClient
		beginTunnelCreateWorkflowForCommand = oldWorkflow
		newTunnelIdempotencyKey = oldKey
		tunnelConnectorAddRuntime = oldRuntime
		connectorEnrollmentLocalClient = oldEnrollment
		tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldProbe, oldRepair
	})

	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", h.stateRoot)
	tunnelHostRuntimeProbe = func(ctx context.Context, _ string) error {
		if !h.ready {
			h.events.add("hostd.probe.unready")
			return errors.New("hostd is stopped")
		}
		if h.event("hostd.readiness") {
			return ctx.Err()
		}
		return nil
	}
	tunnelHostRuntimeRepair = func(ctx context.Context) error {
		if h.event("service.install") {
			return ctx.Err()
		}
		if h.event("service.start") {
			return ctx.Err()
		}
		h.ready = true
		return nil
	}
	tunnelClientForCommand = func(command *cobra.Command) (*api.Client, error) {
		if err := ensureTunnelHostRuntime(command.Context(), h.stateRoot); err != nil {
			return nil, err
		}
		return api.New(h.server.URL, config.Credential{AccessToken: "client-session"}, h.server.Client()), nil
	}
	newTunnelIdempotencyKey = func() (string, error) {
		h.keySequence++
		return fmt.Sprintf("workflow_key_%02d", h.keySequence), nil
	}
	beginTunnelCreateWorkflowForCommand = func(ctx context.Context, request tunnelCreateWorkflowRequest) (tunnelCreateWorkflow, error) {
		h.events.add("workflow.begin")
		h.lastRequest, h.hasRequest = request, true
		nameDigest := sha256.Sum256([]byte(request.Name))
		session, err := tunnelcreatejournal.Begin(ctx, tunnelcreatejournal.Config{
			StateRoot: h.stateRoot, HostID: "host_workflow", NameDigest: hex.EncodeToString(nameDigest[:]),
			RequestDigest: request.RequestDigest, DomainCount: request.DomainCount, ExpiresAt: request.ExpiresAt,
			NewKey: tunnelKey,
		})
		if err != nil {
			return nil, err
		}
		return &recordingTunnelCreateWorkflow{harness: h, session: session}, nil
	}
	connectorEnrollmentLocalClient = func(string) (tunnelConnectorEnrollmentClient, error) {
		h.events.add("hostd.client")
		return h.enrollment, nil
	}
	tunnelConnectorAddRuntime = runProductionTunnelConnectorAdd
	return h
}

func (h *workflowAcceptanceHarness) event(name string) bool {
	h.events.add(name)
	if h.cancelAt == name && h.cancel != nil {
		h.cancel()
		return true
	}
	return false
}

func (h *workflowAcceptanceHarness) serveControlPlane(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels":
		if h.event("control.tunnel.create") {
			w.WriteHeader(499)
			return
		}
		h.createCalls++
		if key := r.Header.Get("Idempotency-Key"); key != "workflow_key_01" {
			h.t.Errorf("tunnel idempotency key=%q", key)
		}
		var input api.TunnelCreateInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			h.t.Errorf("decode tunnel input: %v", err)
			return
		}
		if input.Name != "workflow" || input.AccessMode != "public" || input.Origin != (api.TunnelOriginInput{Scheme: "http", Address: "127.0.0.1:8080"}) {
			h.t.Errorf("tunnel input=%#v", input)
		}
		tunnel := validCommandTunnel()
		tunnel.ID, tunnel.Name, tunnel.AccessMode = "tun_workflow", input.Name, input.AccessMode
		tunnel.ETag = `"tunnel:tun_workflow:1"`
		operation := validCommandOperation("tunnel", tunnel.ID)
		operation.ID = "operation_workflow"
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: tunnel, Operation: operation, Replayed: h.createCalls > 1, Changed: h.createCalls == 1}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_workflow/routes":
		if h.event("control.routes.list") {
			w.WriteHeader(499)
			return
		}
		route := validCommandRoute("route_workflow", "default")
		route.TunnelID = "tun_workflow"
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels/tun_workflow/domains":
		if h.event("control.domain.create") {
			w.WriteHeader(499)
			return
		}
		h.domainCalls++
		if key := r.Header.Get("Idempotency-Key"); key != "workflow_key_02" {
			h.t.Errorf("domain idempotency key=%q", key)
		}
		var input api.TunnelDomainInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Hostname != "app.example.test" || input.RouteID != "route_workflow" {
			h.t.Errorf("domain input=%#v error=%v", input, err)
		}
		domain := validCommandDomain("domain_workflow", "app.example.test")
		domain.TunnelID, domain.RouteID = "tun_workflow", "route_workflow"
		operation := validCommandOperation("domain_binding", domain.ID)
		operation.ID = "operation_domain_workflow"
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainMutation{Domain: domain, Operation: operation, Replayed: h.domainCalls > 1, Changed: h.domainCalls == 1}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_workflow/domains/domain_workflow/instructions":
		if h.event("control.domain.instructions") {
			w.WriteHeader(499)
			return
		}
		instructions := api.TunnelDNSInstructions{
			Schema: api.TunnelV1Schema, Kind: "dns_instructions", TunnelID: "tun_workflow", DomainID: "domain_workflow",
			Hostname: "app.example.test", Provider: "generic", CertificateStrategy: "managed", VerificationState: "waiting_dns",
			Records: []api.TunnelDNSRecord{{Name: "app.example.test", Type: "CNAME", Value: "edge.example.test", TTL: 300}}, Note: "Add this authoritative record.",
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": instructions})
	default:
		h.t.Errorf("unexpected request=%s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (h *workflowAcceptanceHarness) execute(jsonOutput, withDomain bool) (string, string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	h.commandContext, h.cancel = ctx, cancel
	defer cancel()
	out := &workflowAcceptanceWriter{harness: h}
	var stderr bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetContext(ctx)
	command.SetOut(out)
	command.SetErr(&stderr)
	args := []string{"create", "workflow", "--port", "8080"}
	if withDomain {
		args = append(args, "--domain", "app.example.test")
	}
	if jsonOutput {
		args = append(args, "--json")
	}
	command.SetArgs(args)
	err := command.Execute()
	return out.buffer.String(), stderr.String(), err
}

func (h *workflowAcceptanceHarness) assertJournalLockReleased(t *testing.T) {
	t.Helper()
	if !h.hasRequest {
		return
	}
	nameDigest := sha256.Sum256([]byte(h.lastRequest.Name))
	session, err := tunnelcreatejournal.Begin(t.Context(), tunnelcreatejournal.Config{
		StateRoot: h.stateRoot, HostID: "host_workflow", NameDigest: hex.EncodeToString(nameDigest[:]),
		RequestDigest: h.lastRequest.RequestDigest, DomainCount: h.lastRequest.DomainCount, ExpiresAt: h.lastRequest.ExpiresAt,
		NewKey: tunnelKey,
	})
	if err != nil {
		t.Fatalf("workflow lock was not released: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertWorkflowAcceptanceSecretSafe(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		for _, secret := range []string{workflowAcceptanceSecret, "workflow_key_01", "workflow_key_02", "workflow_key_03"} {
			if strings.Contains(value, secret) {
				t.Fatalf("secret %q escaped in %q", secret, value)
			}
		}
	}
}

func TestTunnelCreateWorkflowOrdersServiceControlConnectorDomainAndOutput(t *testing.T) {
	h := newWorkflowAcceptanceHarness(t)
	stdout, stderr, err := h.execute(true, true)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"hostd.probe.unready", "service.install", "service.start", "hostd.readiness", "workflow.begin",
		"control.tunnel.create", "workflow.tunnel", "hostd.readiness", "hostd.client", "hostd.connector.enroll",
		"hostd.connector.activate", "hostd.connector.ready", "workflow.connector", "control.routes.list",
		"control.domain.create", "workflow.domain", "control.domain.instructions", "output", "workflow.complete", "workflow.close",
	}
	if got := h.events.snapshot(); strings.Join(got, "|") != strings.Join(wantOrder, "|") {
		t.Fatalf("order=\n%s\nwant=\n%s", strings.Join(got, "\n"), strings.Join(wantOrder, "\n"))
	}
	if stderr != "" || !json.Valid([]byte(stdout)) || !strings.Contains(stdout, `"kind":"tunnel_create"`) || !strings.Contains(stdout, `"connector_id":"connector_workflow"`) || !strings.Contains(stdout, `"hostname":"app.example.test"`) || !strings.Contains(stdout, `"edge.example.test"`) {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	assertWorkflowAcceptanceSecretSafe(t, stdout, stderr)
	h.assertJournalLockReleased(t)
}

func TestTunnelCreateWorkflowHumanOutputIsFinalAndSecretSafe(t *testing.T) {
	h := newWorkflowAcceptanceHarness(t)
	stdout, stderr, err := h.execute(false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Created tunnel workflow (tun_workflow)", "Connector connector_workflow is ready", "https://123e4567-e89b-42d3-a456-426614174000.tunnels.example.test -> http://127.0.0.1:8080", "DNS for app.example.test:", "app.example.test\tCNAME\tedge.example.test\t300"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("output missing %q: %s", expected, stdout)
		}
	}
	if stderr != "" {
		t.Fatalf("stderr=%q", stderr)
	}
	assertWorkflowAcceptanceSecretSafe(t, stdout, stderr)
}

func TestTunnelCreateWorkflowResumesExactIdempotentRequestAfterConnectorCrash(t *testing.T) {
	h := newWorkflowAcceptanceHarness(t)
	h.enrollment.fail = tunnelenrollment.ErrUnavailable
	firstOut, firstErrOut, err := h.execute(true, false)
	var changed *TunnelCreateChangedError
	if !errors.As(err, &changed) || changed.TunnelID != "tun_workflow" || changed.Stage != "connector activation" || changed.RecoveryCommand != "pb tunnel connector add tun_workflow" {
		t.Fatalf("first error=%T %v", err, err)
	}
	if firstOut != "" || firstErrOut != "" {
		t.Fatalf("first stdout=%q stderr=%q", firstOut, firstErrOut)
	}
	assertWorkflowAcceptanceSecretSafe(t, firstOut, firstErrOut, err.Error())

	secondOut, secondErrOut, err := h.execute(true, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.createCalls != 2 || !strings.Contains(secondOut, `"replayed":true`) || secondErrOut != "" {
		t.Fatalf("create calls=%d stdout=%q stderr=%q", h.createCalls, secondOut, secondErrOut)
	}
	assertWorkflowAcceptanceSecretSafe(t, secondOut, secondErrOut)
	events := strings.Join(h.events.snapshot(), "|")
	if strings.Count(events, "control.tunnel.create") != 2 || strings.Count(events, "workflow.tunnel") != 2 || strings.Count(events, "workflow.complete") != 1 {
		t.Fatalf("resume events=%s", events)
	}
	h.assertJournalLockReleased(t)
}

func TestTunnelCreateWorkflowCancellationStopsAtEveryBoundaryAndReleasesOwnership(t *testing.T) {
	boundaries := []string{
		"service.start", "hostd.readiness", "control.tunnel.create", "workflow.tunnel",
		"hostd.connector.enroll", "hostd.connector.activate", "workflow.connector",
		"control.routes.list", "control.domain.create", "workflow.domain", "control.domain.instructions", "output", "workflow.complete",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			h := newWorkflowAcceptanceHarness(t)
			h.cancelAt = boundary
			stdout, stderr, err := h.execute(true, true)
			if err == nil || !errors.Is(h.commandContext.Err(), context.Canceled) {
				t.Fatalf("boundary=%s error=%T %v context=%v", boundary, err, err, h.commandContext.Err())
			}
			if strings.Contains(strings.Join(h.events.snapshot(), "|"), "workflow.complete|workflow.close") && boundary != "workflow.complete" {
				t.Fatalf("completed after cancellation: %v", h.events.snapshot())
			}
			assertWorkflowAcceptanceSecretSafe(t, stdout, stderr, err.Error())
			h.assertJournalLockReleased(t)
		})
	}
}

func TestTunnelCreateWorkflowHarnessRejectsTrailingOutputSecrets(t *testing.T) {
	// The command's connector projection must remain the safe, deliberately
	// smaller output even though hostd returns a credential reference.
	h := newWorkflowAcceptanceHarness(t)
	stdout, stderr, err := h.execute(true, false)
	if err != nil {
		t.Fatal(err)
	}
	assertWorkflowAcceptanceSecretSafe(t, stdout, stderr)
	var output tunnelCreateOutput
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil || decoder.Decode(&struct{}{}) != io.EOF || output.Connector.ConnectorID != "connector_workflow" {
		t.Fatalf("unsafe output=%q decode=%v", stdout, err)
	}
}

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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/supportbundle"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelcreatejournal"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/spf13/cobra"
)

type cancelAfterWrite struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelAfterWrite) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.cancel()
	return n, err
}

func withTunnelCommandClient(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	old := tunnelClientForCommand
	tunnelClientForCommand = func(*cobra.Command) (*api.Client, error) {
		return api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), nil
	}
	t.Cleanup(func() { tunnelClientForCommand = old })
	oldSelector := resolveTunnelSelectorForCommand
	resolveTunnelSelectorForCommand = func(ctx context.Context, client *api.Client, value string) (string, error) {
		if strings.HasPrefix(value, "tun_") && validTunnelCLIResourceID(value) {
			return value, nil
		}
		return resolveTunnelSelector(ctx, client, value)
	}
	t.Cleanup(func() { resolveTunnelSelectorForCommand = oldSelector })
	oldKey := newTunnelIdempotencyKey
	newTunnelIdempotencyKey = func() (string, error) { return "idem_test", nil }
	t.Cleanup(func() { newTunnelIdempotencyKey = oldKey })
	workflowRoot := t.TempDir()
	oldWorkflow := beginTunnelCreateWorkflowForCommand
	beginTunnelCreateWorkflowForCommand = func(ctx context.Context, request tunnelCreateWorkflowRequest) (tunnelCreateWorkflow, error) {
		nameDigest := sha256.Sum256([]byte(request.Name))
		return tunnelcreatejournal.Begin(ctx, tunnelcreatejournal.Config{StateRoot: workflowRoot, HostID: "host_1", NameDigest: hex.EncodeToString(nameDigest[:]), RequestDigest: request.RequestDigest, DomainCount: request.DomainCount, ExpiresAt: request.ExpiresAt, NewKey: tunnelKey})
	}
	t.Cleanup(func() { beginTunnelCreateWorkflowForCommand = oldWorkflow })
	oldRuntime := tunnelConnectorAddRuntime
	tunnelConnectorAddRuntime = func(command *cobra.Command, tunnelID string) error {
		ready := time.Unix(3, 0).UTC()
		projection := tunnelenrollment.Projection{Schema: tunnelenrollment.Schema, Kind: "tunnel_connector", TunnelID: tunnelID, HostID: "host_1", ConnectorID: "connector_1", OperationID: "operation_connector_1", State: "ready", CredentialReference: "protected-file://paperboat/connector_1", CredentialGeneration: 1, ReadyAt: &ready}
		return tunnelOutput(command, projection, "connector ready")
	}
	t.Cleanup(func() { tunnelConnectorAddRuntime = oldRuntime })
}

func validCommandTunnel() api.Tunnel {
	return api.Tunnel{Schema: api.TunnelV1Schema, Kind: "tunnel", ID: "tun_1", AccountID: "acc_1", Generation: 4, ETag: `"tunnel:tun_1:4"`, Name: "demo", AccessMode: "private", DesiredState: "active", StableEndpointID: "endpoint_1", StableEndpoint: "https://demo.example.test", CreatedByHostID: "host_1", CreatedByActorID: "user_1", SummaryCode: "ready", CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(2, 0).UTC()}
}

func validCommandOperation(kind, id string) api.TunnelOperation {
	return api.TunnelOperation{Schema: api.TunnelV1Schema, Kind: "operation", ID: "operation_1", ResourceKind: kind, ResourceID: id, Phase: "connecting", State: "running", Progress: 1, CorrelationID: "correlation_1", CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}
}

func TestTunnelCommandSurfaceIsExplicitAndSecretSafe(t *testing.T) {
	root := tunnelCobraCommandV1()
	for _, name := range []string{"create", "list", "show", "pause", "resume", "delete", "status", "doctor", "logs", "route", "domain", "connector", "credentials"} {
		if child, _, _ := root.Find([]string{name}); child == nil || child == root {
			t.Fatalf("missing %s", name)
		}
	}
	connector, _, _ := root.Find([]string{"connector"})
	for _, name := range []string{"list", "add", "drain", "revoke"} {
		if child, _, _ := connector.Find([]string{name}); child == nil || child == connector {
			t.Fatalf("missing connector %s", name)
		}
	}
	for _, path := range [][]string{{"route", "add"}, {"route", "update"}, {"route", "remove"}, {"domain", "add"}, {"domain", "verify"}, {"domain", "remove"}, {"domain", "instructions"}, {"credentials", "rotate"}} {
		if child, _, _ := root.Find(path); child == nil || child == root {
			t.Fatalf("missing %v", path)
		}
	}
	for _, forbidden := range []string{"enroll", "enrollment", "token", "secret"} {
		if child, _, _ := connector.Find([]string{forbidden}); child != connector {
			t.Fatalf("unsafe connector command %q exists", forbidden)
		}
	}
	wantRoot := []string{"connector", "create", "credentials", "delete", "doctor", "domain", "list", "logs", "pause", "resume", "route", "show", "status"}
	var gotRoot []string
	for _, child := range root.Commands() {
		if !child.Hidden {
			gotRoot = append(gotRoot, child.Name())
		}
	}
	sort.Strings(gotRoot)
	if strings.Join(gotRoot, ",") != strings.Join(wantRoot, ",") {
		t.Fatalf("tunnel commands=%v want=%v", gotRoot, wantRoot)
	}
	for _, expected := range []struct {
		path []string
		want []string
	}{
		{path: []string{"route"}, want: []string{"add", "list", "remove", "update"}},
		{path: []string{"domain"}, want: []string{"add", "instructions", "list", "remove", "verify"}},
		{path: []string{"connector"}, want: []string{"add", "drain", "list", "revoke"}},
		{path: []string{"credentials"}, want: []string{"rotate"}},
	} {
		parent, _, _ := root.Find(expected.path)
		var got []string
		for _, child := range parent.Commands() {
			if !child.Hidden {
				got = append(got, child.Name())
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(expected.want, ",") {
			t.Fatalf("%v commands=%v want=%v", expected.path, got, expected.want)
		}
	}
	for _, path := range [][]string{{"route", "get"}, {"connector", "get"}} {
		child, _, _ := root.Find(path)
		if child != nil && child.Name() == path[len(path)-1] {
			t.Fatalf("undocumented command is exposed: %v", path)
		}
	}
}

func TestTunnelAndAccessAreRegisteredExactlyOnce(t *testing.T) {
	root := newRootCommand()
	counts := map[string]int{}
	for _, child := range root.Commands() {
		counts[child.Name()]++
	}
	if counts["tunnel"] != 1 || counts["access"] != 1 {
		t.Fatalf("root counts=%v", counts)
	}
	access, _, err := root.Find([]string{"access"})
	if err != nil {
		t.Fatal(err)
	}
	tunnelCount := 0
	for _, child := range access.Commands() {
		if child.Name() == "tunnel" {
			tunnelCount++
		}
	}
	if tunnelCount != 1 {
		t.Fatalf("access tunnel count=%d", tunnelCount)
	}
}

func TestTunnelHelpIsCanonicalAndSecretSafe(t *testing.T) {
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"create", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, required := range []string{"create <name>", "--port", "--from", "--domain", "--private", "--duration", "--wait", "--timeout", "--json"} {
		if !strings.Contains(help, required) {
			t.Fatalf("help missing %q: %s", required, help)
		}
	}
	for _, forbidden := range []string{"enrollment-token", "credential-secret", "private-key"} {
		if strings.Contains(strings.ToLower(help), forbidden) {
			t.Fatalf("unsafe help: %s", help)
		}
	}
}

func TestTunnelDoctorHelpExplainsLocalPreviewAndExplicitWrite(t *testing.T) {
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"doctor", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, required := range []string{"doctor <tunnel>", "--bundle", "--write-bundle", "--bundle-max-bytes", "absolute path", "exact previewed bundle"} {
		if !strings.Contains(help, required) {
			t.Fatalf("doctor help missing %q: %s", required, help)
		}
	}
	if strings.Contains(strings.ToLower(help), "upload") {
		t.Fatalf("doctor help implies upload: %s", help)
	}
}

func TestTunnelCompletionUsesTheCanonicalSurface(t *testing.T) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"__complete", "tunnel", ""})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	completion := output.String()
	for _, required := range []string{"create\t", "list\t", "route\t", "domain\t", "connector\t", "credentials\t"} {
		if !strings.Contains(completion, required) {
			t.Fatalf("completion missing %q: %s", required, completion)
		}
	}
	for _, forbidden := range []string{"enroll\t", "token\t"} {
		if strings.Contains(completion, forbidden) {
			t.Fatalf("unsafe completion %q: %s", forbidden, completion)
		}
	}
}

func TestConnectorAddUsesInjectedRuntimeAndFailsTypedWhenAbsent(t *testing.T) {
	withTunnelCommandClient(t, func(_ http.ResponseWriter, request *http.Request) {
		t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
	})
	old := tunnelConnectorAddRuntime
	t.Cleanup(func() { tunnelConnectorAddRuntime = old })
	tunnelConnectorAddRuntime = nil
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"connector", "add", "tun_1"})
	if err := command.Execute(); !errors.Is(err, ErrTunnelConnectorAddRequiresRuntime) {
		t.Fatalf("error=%v", err)
	}
	called := ""
	tunnelConnectorAddRuntime = func(_ *cobra.Command, tunnel string) error { called = tunnel; return nil }
	command = tunnelCobraCommandV1()
	command.SetArgs([]string{"connector", "add", "tun_1"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if called != "tun_1" {
		t.Fatalf("called=%q", called)
	}
}

func TestTunnelCreateValidatesBeforeConstructingClient(t *testing.T) {
	old := tunnelClientForCommand
	t.Cleanup(func() { tunnelClientForCommand = old })
	called := false
	tunnelClientForCommand = func(*cobra.Command) (*api.Client, error) { called = true; return nil, errors.New("must not be called") }
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"create", "bad name", "--port", "80"})
	if err := command.Execute(); err == nil {
		t.Fatal("expected validation error")
	}
	if called {
		t.Fatal("client was constructed before validation")
	}
}

func TestTunnelLogsFollowIsCancellationSafeAndRedacted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	requests := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		entry := api.TunnelLogEntry{Schema: api.TunnelV1Schema, Kind: "log_entry", ID: "log_1", TunnelID: "tun_1", Level: "info", Component: "edge", Code: "ready", Message: "Bearer hidden", Metadata: map[string]any{"access_token": "hidden"}, OccurredAt: time.Unix(1, 0).UTC(), Cursor: "cur_1"}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelLogPage{Items: []api.TunnelLogEntry{entry}}})
	})
	output := &cancelAfterWrite{cancel: cancel}
	command := tunnelCobraCommandV1()
	command.SetContext(ctx)
	command.SetOut(output)
	command.SetArgs([]string{"logs", "tun_1", "--follow", "--interval", "250ms", "--json"})
	err := command.Execute()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}
	if strings.Contains(output.String(), "hidden") || !strings.Contains(output.String(), "[REDACTED]") {
		t.Fatalf("output=%s", output.String())
	}
}

func TestTunnelLogsRejectsInvalidBoundsBeforeRequest(t *testing.T) {
	requests := 0
	withTunnelCommandClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"logs", "tun_1", "--limit", "201"})
	if err := command.Execute(); err == nil {
		t.Fatal("expected limit error")
	}
	if requests != 0 {
		t.Fatalf("requests=%d", requests)
	}
}

type tunnelCommandFailingWriter struct{}

func (tunnelCommandFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output failed")
}

func TestTunnelHumanLogOutputReturnsWriterError(t *testing.T) {
	command := tunnelCobraCommandV1()
	command.SetOut(tunnelCommandFailingWriter{})
	command.SetArgs([]string{"logs", "tun_1"})
	withTunnelCommandClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelLogPage{
			Items: []api.TunnelLogEntry{{Schema: api.TunnelV1Schema, Kind: "log_entry", ID: "log_1", TunnelID: "tun_1", OccurredAt: time.Unix(1, 0).UTC(), Level: "info", Component: "edge", Code: "ready", Message: "ready"}},
		}})
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "output failed") {
		t.Fatalf("error=%v", err)
	}
}

func TestNormalizeTunnelCLIPathPrefixRejectsEmbeddedWildcards(t *testing.T) {
	for _, value := range []string{"/api/*/v1", "/api**", "/api*tail"} {
		if _, err := normalizeTunnelCLIPathPrefix(value); err == nil {
			t.Fatalf("path %q was accepted", value)
		}
	}
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "/", want: "/"},
		{input: "/api/*", want: "/api/"},
		{input: "/api/v1", want: "/api/v1"},
	} {
		if got, err := normalizeTunnelCLIPathPrefix(test.input); err != nil || got != test.want {
			t.Fatalf("normalize(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
}

func TestTunnelDoctorPrintsDeterministicHealth(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/tunnels" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelPage{Items: []api.Tunnel{validCommandTunnel()}}})
			return
		}
		d := api.TunnelHealthDimension{Status: "healthy", Code: "ready"}
		health := api.TunnelHealth{Schema: api.TunnelV1Schema, Kind: "health", ResourceKind: "tunnel", ResourceID: "tun_1", OverallCode: "ready", Summary: "Tunnel is ready.", RepairAction: "none", Since: time.Unix(1, 0).UTC(), Dimensions: api.TunnelHealthDimensions{Service: d, Edge: d, Config: d, Route: d, Origin: d, DNS: d, Certificate: d, Access: d, Update: d}}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": health})
	})
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"doctor", "demo"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "Tunnel tun_1: ready\nTunnel is ready.\n" +
		"service      healthy (ready)\nedge         healthy (ready)\nconfig       healthy (ready)\n" +
		"route        healthy (ready)\norigin       healthy (ready)\ndns          healthy (ready)\n" +
		"certificate  healthy (ready)\naccess       healthy (ready)\nupdate       healthy (ready)\nRepair: none\n"
	if output.String() != want {
		t.Fatalf("output=%q", output.String())
	}
}

func TestTunnelDoctorBundleRequiresPreviewAndExplicitWrite(t *testing.T) {
	oldReport := tunnelDoctorLocalReportForCommand
	oldDNS := tunnelDoctorDNSCheckForCommand
	t.Cleanup(func() {
		tunnelDoctorLocalReportForCommand = oldReport
		tunnelDoctorDNSCheckForCommand = oldDNS
	})
	tunnelDoctorLocalReportForCommand = func(context.Context) (localDoctorReport, error) {
		return localDoctorReport{
			HostRuntime: "ready", IdentityState: "valid", CredentialState: "valid",
			StateRoot: "/Users/alice/private", MachineID: "machine_private_1", InboxPath: "/Users/alice/inbox",
			RecoveryActions: []string{"authorization=doctor-private-secret"},
		}, nil
	}
	tunnelDoctorDNSCheckForCommand = func(context.Context) bool { return true }
	dimension := api.TunnelHealthDimension{Status: "healthy", Code: "ready"}
	health := api.TunnelHealth{Schema: api.TunnelV1Schema, Kind: "health", ResourceKind: "tunnel", ResourceID: "tun_1", OverallCode: "ready", Summary: "Tunnel is ready.", RepairAction: "none", Since: time.Unix(1, 0).UTC(), Dimensions: api.TunnelHealthDimensions{Service: dimension, Edge: dimension, Config: dimension, Route: dimension, Origin: dimension, DNS: dimension, Certificate: dimension, Access: dimension, Update: dimension}}
	withTunnelCommandClient(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/tunnels":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.TunnelPage{Items: []api.Tunnel{validCommandTunnel()}}})
		case "/v1/tunnels/tun_1/status":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": health})
		default:
			t.Fatalf("request=%s", request.URL.String())
		}
	})

	outputPath := filepath.Join(realCommandTempDir(t), "tunnel-support.json")
	previewOutput := executeTunnelDoctorJSON(t, "demo", outputPath, false)
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote output: %v", err)
	}
	if previewOutput.Bundle == nil || previewOutput.Written != nil || previewOutput.Bundle.Path != outputPath || previewOutput.Bundle.SizeBytes == 0 || previewOutput.Bundle.SHA256 == "" || len(previewOutput.Bundle.Manifest.Items) != 2 {
		t.Fatalf("preview = %#v", previewOutput)
	}
	writtenOutput := executeTunnelDoctorJSON(t, "demo", outputPath, true)
	if writtenOutput.Bundle == nil || writtenOutput.Written == nil || writtenOutput.Bundle.SHA256 != previewOutput.Bundle.SHA256 || writtenOutput.Written.SHA256 != previewOutput.Bundle.SHA256 {
		t.Fatalf("written output = %#v", writtenOutput)
	}
	written, err := os.ReadFile(outputPath)
	if err != nil || string(written) != string(mustPreviewBytes(t, health)) {
		t.Fatalf("written bundle changed: bytes=%d err=%v", len(written), err)
	}
	for _, unsafe := range []string{"/Users/alice", "machine_private_1", "doctor-private-secret"} {
		if bytes.Contains(written, []byte(unsafe)) {
			t.Fatalf("private value %q present in bundle", unsafe)
		}
	}
	if !bytes.Contains(written, []byte("unavailable")) {
		t.Fatal("typed unavailable evidence is missing")
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(outputPath)
		if statErr != nil {
			t.Fatalf("bundle stat: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("bundle mode=%v", info.Mode().Perm())
		}
	}
}

func TestTunnelDoctorBundleValidatesBeforeNetwork(t *testing.T) {
	requests := 0
	withTunnelCommandClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	for _, arguments := range [][]string{
		{"doctor", "demo", "--write-bundle"},
		{"doctor", "demo", "--bundle", "relative.json"},
		{"doctor", "demo", "--bundle", filepath.Join(realCommandTempDir(t), "bundle.json"), "--bundle-max-bytes", "1024"},
	} {
		command := tunnelCobraCommandV1()
		command.SetArgs(arguments)
		if err := command.Execute(); err == nil {
			t.Fatalf("arguments %v succeeded", arguments)
		}
	}
	if requests != 0 {
		t.Fatalf("requests before validation = %d", requests)
	}
}

func TestTunnelDoctorBundleCollectorHonorsCancellation(t *testing.T) {
	oldReport := tunnelDoctorLocalReportForCommand
	t.Cleanup(func() { tunnelDoctorLocalReportForCommand = oldReport })
	called := false
	tunnelDoctorLocalReportForCommand = func(ctx context.Context) (localDoctorReport, error) {
		called = true
		<-ctx.Done()
		return localDoctorReport{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := buildTunnelDoctorBundle(ctx, api.TunnelHealth{}, tunnelDoctorBundleDefaultBytes)
	var typed *supportbundle.Error
	if !errors.As(err, &typed) || typed.Code != supportbundle.ErrorCanceled || called {
		t.Fatalf("cancellation error=%v called=%t", err, called)
	}
}

func TestResolveTunnelSelectorRejectsIDNameCollision(t *testing.T) {
	canonical := validCommandTunnel()
	canonical.Name = "canonical"
	other := validCommandTunnel()
	other.ID, other.Name, other.ETag = "tun_2", "tun_1", `"tunnel:tun_2:4"`
	client := tunnelSelectorTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/tunnels/tun_1":
			writer.Header().Set("ETag", canonical.ETag)
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": canonical})
		case "/v1/tunnels":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.TunnelPage{Items: []api.Tunnel{other}}})
		default:
			t.Fatalf("request=%s", request.URL.String())
		}
	})
	var ambiguous *TunnelSelectorAmbiguousError
	if _, err := resolveTunnelSelector(t.Context(), client, "tun_1"); !errors.As(err, &ambiguous) {
		t.Fatalf("collision error = %v", err)
	}
}

func TestResolveTunnelSelectorPreservesCanonicalIDWhenUnambiguous(t *testing.T) {
	canonical := validCommandTunnel()
	canonical.Name = "canonical"
	var requests []string
	client := tunnelSelectorTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.Path)
		switch request.URL.Path {
		case "/v1/tunnels/tun_1":
			writer.Header().Set("ETag", canonical.ETag)
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": canonical})
		case "/v1/tunnels":
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.TunnelPage{}})
		default:
			t.Fatalf("request=%s", request.URL.String())
		}
	})
	if id, err := resolveTunnelSelector(t.Context(), client, "tun_1"); err != nil || id != "tun_1" {
		t.Fatalf("canonical selector = %q, %v", id, err)
	}
	if strings.Join(requests, ",") != "/v1/tunnels/tun_1,/v1/tunnels" {
		t.Fatalf("requests=%v", requests)
	}
}

func TestResolveTunnelSelectorPaginatesAndRejectsCursorCycle(t *testing.T) {
	target := validCommandTunnel()
	target.Name = "target"
	client := tunnelSelectorTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		cursor := request.URL.Query().Get("cursor")
		page := api.TunnelPage{NextCursor: "page_2"}
		if cursor == "page_2" {
			page = api.TunnelPage{Items: []api.Tunnel{target}}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": page})
	})
	if id, err := resolveTunnelSelector(t.Context(), client, "target"); err != nil || id != target.ID {
		t.Fatalf("paginated selector = %q, %v", id, err)
	}

	cycleClient := tunnelSelectorTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.TunnelPage{NextCursor: "cycle"}})
	})
	if _, err := resolveTunnelSelector(t.Context(), cycleClient, "missing"); !errors.Is(err, api.ErrUnsafeTunnelResponse) {
		t.Fatalf("cursor cycle error = %v", err)
	}

	pages := 0
	boundedClient := tunnelSelectorTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		pages++
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.TunnelPage{NextCursor: fmt.Sprintf("page_%d", pages)}})
	})
	if _, err := resolveTunnelSelector(t.Context(), boundedClient, "missing"); !errors.Is(err, api.ErrUnsafeTunnelResponse) || pages != 10 {
		t.Fatalf("bounded enumeration error=%v pages=%d", err, pages)
	}
}

func executeTunnelDoctorJSON(t *testing.T, selector, outputPath string, write bool) tunnelDoctorOutput {
	t.Helper()
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	arguments := []string{"doctor", selector, "--bundle", outputPath, "--json"}
	if write {
		arguments = append(arguments, "--write-bundle")
	}
	command.SetArgs(arguments)
	if err := command.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var result tunnelDoctorOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v: %s", err, output.String())
	}
	return result
}

func mustPreviewBytes(t *testing.T, health api.TunnelHealth) []byte {
	t.Helper()
	builder, preview, err := buildTunnelDoctorBundle(t.Context(), health, tunnelDoctorBundleDefaultBytes)
	if err != nil || builder == nil {
		t.Fatalf("build preview: %v", err)
	}
	return preview.Bytes()
}

func tunnelSelectorTestClient(t *testing.T, handler http.HandlerFunc) *api.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
}

func realCommandTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return directory
}

func TestCollectTunnelDoctorLocalReportUsesNoProxyAndStrictHealthJSON(t *testing.T) {
	proxyCalls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		http.Error(w, "proxy must not receive loopback diagnostics", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	tests := []struct {
		name       string
		headers    []string
		body       string
		status     int
		location   string
		wantStatus string
	}{
		{name: "valid", headers: []string{"application/json"}, body: `{"live":true}`, wantStatus: "ready"},
		{name: "wrong content type", headers: []string{"text/plain"}, body: `{"live":true}`, wantStatus: "unhealthy"},
		{name: "multiple content types", headers: []string{"application/json", "application/json"}, body: `{"live":true}`, wantStatus: "unhealthy"},
		{name: "duplicate live", headers: []string{"application/json"}, body: `{"live":true,"live":true}`, wantStatus: "unhealthy"},
		{name: "unknown field", headers: []string{"application/json"}, body: `{"live":true,"secret":false}`, wantStatus: "unhealthy"},
		{name: "trailing data", headers: []string{"application/json"}, body: `{"live":true}{}`, wantStatus: "unhealthy"},
		{name: "oversized body", headers: []string{"application/json"}, body: `{"live":true,"padding":"` + strings.Repeat("x", 64<<10) + `"}`, wantStatus: "unhealthy"},
		{name: "redirect", headers: []string{"application/json"}, body: `{"live":true}`, status: http.StatusFound, location: "/other", wantStatus: "unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, value := range test.headers {
					w.Header().Add("Content-Type", value)
				}
				if test.location != "" {
					w.Header().Set("Location", test.location)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			stateRoot := t.TempDir()
			runtimeDirectory := filepath.Join(stateRoot, "runtime")
			if err := os.Mkdir(runtimeDirectory, 0o700); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			descriptor := []byte(fmt.Sprintf(`{"schema":"paperboat.worker-local/v1","listen_address":%q}`, strings.TrimPrefix(server.URL, "http://")))
			if err := os.WriteFile(filepath.Join(runtimeDirectory, "worker-local.json"), descriptor, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
			report, err := collectTunnelDoctorLocalReport(t.Context())
			if err != nil || report.HostRuntime != test.wantStatus {
				t.Fatalf("report=%#v error=%v", report, err)
			}
		})
	}
	if proxyCalls != 0 {
		t.Fatalf("proxy calls = %d", proxyCalls)
	}
}

func TestResolveTunnelRouteAndDomainAreAmbiguitySafeAndBounded(t *testing.T) {
	t.Run("route ID-name collision", func(t *testing.T) {
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			first := validCommandRoute("route_1", "route_2")
			second := validCommandRoute("route_2", "default")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{first, second}}})
		})
		_, err := resolveTunnelRoute(t.Context(), client, "tun_1", "route_2")
		var ambiguous *TunnelRouteSelectorAmbiguousError
		if !errors.As(err, &ambiguous) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("route duplicate and pagination", func(t *testing.T) {
		requests := 0
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests++
			route := validCommandRoute("route_1", "api")
			page := api.TunnelRoutePage{Items: []api.TunnelRoute{route}, NextCursor: "next"}
			if r.URL.Query().Get("cursor") == "next" {
				page.NextCursor = ""
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": page})
		})
		route, err := resolveTunnelRoute(t.Context(), client, "tun_1", "api")
		if err != nil || route.ID != "route_1" || requests != 2 {
			t.Fatalf("route=%#v requests=%d error=%v", route, requests, err)
		}
	})
	t.Run("route cursor cycle", func(t *testing.T) {
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{NextCursor: "same"}})
		})
		_, err := resolveTunnelRoute(t.Context(), client, "tun_1", "missing")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("route ten-page fence", func(t *testing.T) {
		requests := 0
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			requests++
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{NextCursor: fmt.Sprintf("page-%d", requests)}})
		})
		_, err := resolveTunnelRoute(t.Context(), client, "tun_1", "missing")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) || requests != 10 {
			t.Fatalf("error=%v requests=%d", err, requests)
		}
	})
	t.Run("domain ID-hostname collision", func(t *testing.T) {
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			first := validCommandDomain("domain_1", "domain-2.example")
			second := validCommandDomain("domain-2.example", "app.example.test")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{Items: []api.TunnelDomain{first, second}}})
		})
		_, err := resolveTunnelDomain(t.Context(), client, "tun_1", "domain-2.example")
		var ambiguous *TunnelDomainSelectorAmbiguousError
		if !errors.As(err, &ambiguous) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("domain pagination and cursor cycle", func(t *testing.T) {
		requests := 0
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests++
			page := api.TunnelDomainPage{NextCursor: "next"}
			if r.URL.Query().Get("cursor") == "next" {
				page.Items = []api.TunnelDomain{validCommandDomain("domain_1", "app.example.test")}
				page.NextCursor = ""
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": page})
		})
		domain, err := resolveTunnelDomain(t.Context(), client, "tun_1", "APP.EXAMPLE.TEST")
		if err != nil || domain.ID != "domain_1" || requests != 2 {
			t.Fatalf("domain=%#v requests=%d error=%v", domain, requests, err)
		}
	})
	t.Run("domain cursor cycle", func(t *testing.T) {
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{NextCursor: "same"}})
		})
		_, err := resolveTunnelDomain(t.Context(), client, "tun_1", "missing.example.test")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("domain ten-page fence", func(t *testing.T) {
		requests := 0
		client := tunnelSelectorTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			requests++
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{NextCursor: fmt.Sprintf("page-%d", requests)}})
		})
		_, err := resolveTunnelDomain(t.Context(), client, "tun_1", "missing.example.test")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) || requests != 10 {
			t.Fatalf("error=%v requests=%d", err, requests)
		}
	})
}

func validCommandRoute(id, name string) api.TunnelRoute {
	return api.TunnelRoute{Schema: api.TunnelV1Schema, Kind: "route", ID: id, TunnelID: "tun_1", Name: name, Protocol: "http", HostMatch: api.TunnelRouteHostMatch{Type: "catch_all"}, Origin: api.TunnelRouteOrigin{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true}, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: `"route:` + id + `:1"`}
}

func validCommandDomain(id, hostname string) api.TunnelDomain {
	return api.TunnelDomain{Schema: api.TunnelV1Schema, Kind: "domain_binding", ID: id, AccountID: "account_1", TunnelID: "tun_1", RouteID: "route_1", Hostname: hostname, MatchType: "exact", State: "ready", DNS: api.TunnelDomainDNS{Target: "edge.example.test"}, Certificate: api.TunnelDomainCertificate{State: "ready"}, Generation: 1, ETag: `"domain:` + id + `:1"`}
}

func TestTunnelNameSelectorResolvesToDurableID(t *testing.T) {
	var requests []string
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		tunnel := validCommandTunnel()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelPage{Items: []api.Tunnel{tunnel}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1":
			w.Header().Set("ETag", tunnel.ETag)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": tunnel})
		default:
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
	})
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"show", "demo"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(requests, ",") != "GET /v1/tunnels,GET /v1/tunnels/tun_1" || !strings.Contains(output.String(), "tun_1") {
		t.Fatalf("requests=%v output=%q", requests, output.String())
	}
}

func TestTunnelDeleteRequiresConfirmationAndUsesCurrentETag(t *testing.T) {
	requests := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		tunnel := validCommandTunnel()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Header().Set("ETag", tunnel.ETag)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": tunnel})
			return
		}
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("If-Match") != tunnel.ETag || r.Header.Get("Idempotency-Key") != "idem_test" {
			t.Fatalf("headers = %#v", r.Header)
		}
		tunnel.DesiredState = "deleted"
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: tunnel, Operation: validCommandOperation("tunnel", tunnel.ID)}})
	})
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"delete", "tun_1"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("requests before confirmation = %d", requests)
	}
	var output bytes.Buffer
	command = tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"delete", "tun_1", "--yes", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	if strings.Contains(strings.ToLower(output.String()), "secret") {
		t.Fatalf("unsafe output: %s", output.String())
	}
}

func TestTunnelCreateUsesCanonicalInputAndJSONOutput(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Idempotency-Key") != "idem_test" {
			t.Fatalf("idempotency = %q", r.Header.Get("Idempotency-Key"))
		}
		var body api.TunnelCreateInput
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AccessMode != "private" || body.Origin.Scheme != "https" || body.Origin.Address != "origin.example:443" {
			t.Fatalf("body = %#v", body)
		}
		value := validCommandTunnel()
		value.Generation = 1
		value.ETag = `"tunnel:tun_1:1"`
		value.Name = body.Name
		value.AccessMode = body.AccessMode
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID)}})
	})
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"create", "demo", "--from", "https://origin.example:443", "--private", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"id":"tun_1"`) {
		t.Fatalf("output = %s", output.String())
	}
}

func TestTunnelCreateReportsPartialDomainFailureAndUsesFreshKeys(t *testing.T) {
	var keys []string
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		if key := r.Header.Get("Idempotency-Key"); key != "" {
			keys = append(keys, key)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels":
			tunnel := validCommandTunnel()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: tunnel, Operation: validCommandOperation("tunnel", tunnel.ID)}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1/routes":
			route := api.TunnelRoute{Schema: api.TunnelV1Schema, Kind: "route", ID: "route_1", TunnelID: "tun_1", Name: "default", Protocol: "http", HostMatch: api.TunnelRouteHostMatch{Type: "catch_all"}, Origin: api.TunnelRouteOrigin{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true}, Priority: 100, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: `"route:route_1:1"`}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels/tun_1/domains":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"domain_conflict","message":"domain is already bound"}}`))
		default:
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
	})
	sequence := 0
	newTunnelIdempotencyKey = func() (string, error) { sequence++; return fmt.Sprintf("idem_%d", sequence), nil }
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"create", "demo", "--port", "8080", "--domain", "app.example.test"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "tunnel tun_1 was created") || !strings.Contains(err.Error(), "app.example.test") {
		t.Fatalf("error=%v", err)
	}
	if strings.Join(keys, ",") != "idem_1,idem_2" {
		t.Fatalf("keys=%v", keys)
	}
}

func TestTunnelCreateConnectorOutcomeIsTypedAndPreservesRecovery(t *testing.T) {
	for _, test := range []struct {
		name        string
		runtimeErr  error
		wantOutcome string
	}{
		{name: "known failure", runtimeErr: tunnelenrollment.ErrForbidden, wantOutcome: "failed"},
		{name: "uncertain local RPC", runtimeErr: tunnelenrollment.ErrUnavailable, wantOutcome: "has an uncertain outcome"},
	} {
		t.Run(test.name, func(t *testing.T) {
			withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels" {
					t.Fatalf("request=%s %s", r.Method, r.URL.Path)
				}
				value := validCommandTunnel()
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID), Changed: true}})
			})
			tunnelConnectorAddRuntime = func(*cobra.Command, string) error { return test.runtimeErr }
			command := tunnelCobraCommandV1()
			command.SetArgs([]string{"create", "demo", "--port", "8080", "--json"})
			err := command.Execute()
			var changed *TunnelCreateChangedError
			if !errors.As(err, &changed) || changed.TunnelID != "tun_1" || changed.Outcome != test.wantOutcome || changed.RecoveryCommand != "pb tunnel connector add tun_1" || !errors.Is(err, test.runtimeErr) {
				t.Fatalf("error=%#v typed=%#v", err, changed)
			}
			if !strings.Contains(err.Error(), "tunnel was preserved") || !strings.Contains(err.Error(), "pb tunnel connector add tun_1") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTunnelCreateReplayResumesConnectorAndEmitsOneCanonicalDocument(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		value := validCommandTunnel()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID), Replayed: true}})
	})
	runtimeCalls := 0
	originalRuntime := tunnelConnectorAddRuntime
	tunnelConnectorAddRuntime = func(command *cobra.Command, tunnelID string) error {
		runtimeCalls++
		return originalRuntime(command, tunnelID)
	}
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"create", "demo", "--port", "8080", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if runtimeCalls != 1 || strings.Count(strings.TrimSpace(output.String()), "\n") != 0 || !strings.Contains(output.String(), `"kind":"tunnel_create"`) || !strings.Contains(output.String(), `"replayed":true`) {
		t.Fatalf("calls=%d output=%q", runtimeCalls, output.String())
	}
}

func TestTunnelCreateProcessRetryReportsExactExistingTunnelWithoutAttaching(t *testing.T) {
	connectorCalls := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"tunnel_name_conflict","message":"A tunnel with this name already exists in the account."}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels":
			existing := validCommandTunnel()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelPage{Items: []api.Tunnel{existing}}})
		default:
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
	})
	tunnelConnectorAddRuntime = func(*cobra.Command, string) error {
		connectorCalls++
		return nil
	}
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"create", "demo", "--port", "8080"})
	err := command.Execute()
	var existing *TunnelCreateExistingError
	if !errors.As(err, &existing) || existing.TunnelID != "tun_1" || existing.Name != "demo" || existing.RecoveryCommand != "pb tunnel show tun_1" {
		t.Fatalf("error=%#v existing=%#v", err, existing)
	}
	if connectorCalls != 0 || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), "pb tunnel show tun_1") {
		t.Fatalf("connector calls=%d error=%v", connectorCalls, err)
	}
}

func TestTunnelCreateInterruptedRetryReusesJournalAndCanonicalOutput(t *testing.T) {
	createCalls := 0
	var keys []string
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		createCalls++
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		value := validCommandTunnel()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID), Replayed: createCalls > 1, Changed: createCalls == 1}})
	})
	readyRuntime := tunnelConnectorAddRuntime
	tunnelConnectorAddRuntime = func(*cobra.Command, string) error { return tunnelenrollment.ErrUnavailable }
	first := tunnelCobraCommandV1()
	first.SetArgs([]string{"create", "demo", "--port", "8080", "--json"})
	if err := first.Execute(); err == nil {
		t.Fatal("interrupted create unexpectedly succeeded")
	}
	tunnelConnectorAddRuntime = readyRuntime
	var output bytes.Buffer
	second := tunnelCobraCommandV1()
	second.SetOut(&output)
	second.SetArgs([]string{"create", "demo", "--port", "8080", "--json"})
	if err := second.Execute(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if createCalls != 2 || len(keys) != 2 || keys[0] != keys[1] || keys[0] != "idem_test" {
		t.Fatalf("calls=%d keys=%v", createCalls, keys)
	}
	if strings.Count(strings.TrimSpace(output.String()), "\n") != 0 || !strings.Contains(output.String(), `"kind":"tunnel_create"`) || !strings.Contains(output.String(), `"replayed":true`) {
		t.Fatalf("output=%q", output.String())
	}
}

func TestTunnelCreateInterruptedRetryWithDifferentInputFailsBeforeNetwork(t *testing.T) {
	createCalls := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, _ *http.Request) {
		createCalls++
		value := validCommandTunnel()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID), Changed: true}})
	})
	tunnelConnectorAddRuntime = func(*cobra.Command, string) error { return tunnelenrollment.ErrUnavailable }
	first := tunnelCobraCommandV1()
	first.SetArgs([]string{"create", "demo", "--port", "8080"})
	if err := first.Execute(); err == nil {
		t.Fatal("interrupted create unexpectedly succeeded")
	}
	second := tunnelCobraCommandV1()
	second.SetArgs([]string{"create", "demo", "--port", "9090"})
	err := second.Execute()
	if !errors.Is(err, tunnelcreatejournal.ErrRequestMismatch) || createCalls != 1 {
		t.Fatalf("error=%v create calls=%d", err, createCalls)
	}
}

func TestTunnelMutationWaitUsesBoundedOperationReadsAndSameMutationKey(t *testing.T) {
	oldInterval := tunnelOperationPollInterval
	tunnelOperationPollInterval = time.Millisecond
	t.Cleanup(func() { tunnelOperationPollInterval = oldInterval })
	operationReads := 0
	mutationCalls := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		tunnel := validCommandTunnel()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1":
			w.Header().Set("ETag", tunnel.ETag)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": tunnel})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels/tun_1/pause":
			mutationCalls++
			if r.Header.Get("Idempotency-Key") != "idem_test" || r.Header.Get("If-Match") != tunnel.ETag {
				t.Fatalf("headers=%v", r.Header)
			}
			tunnel.DesiredState = "paused"
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: tunnel, Operation: validCommandOperation("tunnel", tunnel.ID), Changed: true}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/operations/operation_1":
			operationReads++
			operation := validCommandOperation("tunnel", tunnel.ID)
			operation.Phase, operation.State, operation.Progress = "ready", "succeeded", 100
			operation.UpdatedAt = time.Unix(2, 0).UTC()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": operation})
		default:
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
	})
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"pause", "tun_1", "--wait", "--timeout", "1s"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if mutationCalls != 1 || operationReads != 1 {
		t.Fatalf("mutation=%d operation reads=%d", mutationCalls, operationReads)
	}
}

func TestTunnelMutationRejectsInvalidWaitBeforeRequest(t *testing.T) {
	requests := 0
	withTunnelCommandClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"pause", "tun_1", "--wait", "--timeout", "500ms"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "between 1s") {
		t.Fatalf("error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestTunnelRoutePrivateTCPAndPathClearUseCanonicalWireShapes(t *testing.T) {
	t.Run("private tcp add", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			var input api.TunnelRouteInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.Protocol != "tcp_private" || input.Origin.Scheme != "tcp" || input.Origin.Address != "127.0.0.1:22" || input.HostMatch.Type != "catch_all" {
				t.Fatalf("input=%#v", input)
			}
			route := api.TunnelRoute{Schema: api.TunnelV1Schema, Kind: "route", ID: "route_1", TunnelID: "tun_1", Name: "ssh", Protocol: "tcp_private", HostMatch: api.TunnelRouteHostMatch{Type: "catch_all"}, Origin: input.Origin, Priority: 0, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: `"route:route_1:1"`}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: route, Operation: validCommandOperation("route", route.ID), Changed: true}})
		})
		command := tunnelCobraCommandV1()
		command.SetArgs([]string{"route", "add", "tun_1", "--name", "ssh", "--protocol", "tcp_private", "--to", "tcp://127.0.0.1:22"})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("clear path", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			route := api.TunnelRoute{Schema: api.TunnelV1Schema, Kind: "route", ID: "route_1", TunnelID: "tun_1", Name: "api", Protocol: "http", HostMatch: api.TunnelRouteHostMatch{Type: "catch_all"}, PathPrefix: stringPointer("/api"), Origin: api.TunnelRouteOrigin{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true}, Priority: 0, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: `"route:route_1:1"`}
			if r.Method == http.MethodGet {
				if r.URL.Path != "/v1/tunnels/tun_1/routes" {
					t.Fatalf("path=%s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
				return
			}
			if r.Method != http.MethodPatch || r.URL.Path != "/v1/tunnels/tun_1/routes/route_1" {
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if value, present := body["path_prefix"]; !present || value != nil {
				t.Fatalf("body=%#v", body)
			}
			route.PathPrefix = nil
			route.Generation = 2
			route.ETag = `"route:route_1:2"`
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: route, Operation: validCommandOperation("route", route.ID), Changed: true}})
		})
		command := tunnelCobraCommandV1()
		command.SetArgs([]string{"route", "update", "tun_1", "route_1", "--clear-path"})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})
}

func stringPointer(value string) *string { return &value }

func TestTunnelRouteSelectorsResolveNamesToCanonicalIDs(t *testing.T) {
	route := api.TunnelRoute{Schema: api.TunnelV1Schema, Kind: "route", ID: "route_1", TunnelID: "tun_1", Name: "default", Protocol: "http", HostMatch: api.TunnelRouteHostMatch{Type: "catch_all"}, Origin: api.TunnelRouteOrigin{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true}, Priority: 0, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 1, ETag: `"route:route_1:1"`}

	t.Run("domain add", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1/routes":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
			case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels/tun_1/domains":
				var input api.TunnelDomainInput
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Fatal(err)
				}
				if input.RouteID != route.ID {
					t.Fatalf("route id=%q", input.RouteID)
				}
				domain := api.TunnelDomain{Schema: api.TunnelV1Schema, Kind: "domain_binding", ID: "domain_1", AccountID: "account_1", TunnelID: "tun_1", RouteID: route.ID, Hostname: "app.example.test", MatchType: "exact", State: "waiting_dns", DNS: api.TunnelDomainDNS{Target: "edge.example.test"}, Certificate: api.TunnelDomainCertificate{State: "not_requested"}, Generation: 1, ETag: `"domain:domain_1:1"`}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainMutation{Domain: domain, Operation: validCommandOperation("domain_binding", domain.ID), Changed: true}})
			default:
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
		})
		command := tunnelCobraCommandV1()
		command.SetArgs([]string{"domain", "add", "tun_1", "app.example.test", "--route", "default"})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("route update", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1/routes":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
			case r.Method == http.MethodPatch && r.URL.Path == "/v1/tunnels/tun_1/routes/route_1":
				if r.Header.Get("If-Match") != route.ETag {
					t.Fatalf("if-match=%q", r.Header.Get("If-Match"))
				}
				updated := route
				updated.Name = "renamed"
				updated.Generation = 2
				updated.ETag = `"route:route_1:2"`
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: updated, Operation: validCommandOperation("route", route.ID), Changed: true}})
			default:
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
		})
		command := tunnelCobraCommandV1()
		command.SetArgs([]string{"route", "update", "tun_1", "default", "--name", "renamed"})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("route remove", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1/routes":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/tunnels/tun_1/routes/route_1":
				if r.Header.Get("If-Match") != route.ETag {
					t.Fatalf("if-match=%q", r.Header.Get("If-Match"))
				}
				removed := route
				removed.DesiredState = "deleted"
				removed.Generation = 2
				removed.ETag = `"route:route_1:2"`
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: removed, Operation: validCommandOperation("route", route.ID), Changed: true}})
			default:
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
		})
		command := tunnelCobraCommandV1()
		command.SetArgs([]string{"route", "remove", "tun_1", "default", "--yes"})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTunnelDomainInstructionsResolveHostnameAndRenderAuthoritativeRecords(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		domain := api.TunnelDomain{Schema: api.TunnelV1Schema, Kind: "domain_binding", ID: "domain_1", AccountID: "account_1", TunnelID: "tun_1", RouteID: "route_1", Hostname: "app.example.test", MatchType: "exact", State: "waiting_dns", DNS: api.TunnelDomainDNS{Target: "edge.example.test"}, Certificate: api.TunnelDomainCertificate{State: "not_requested"}, Generation: 1, ETag: `"domain:domain_1:1"`}
		switch r.URL.Path {
		case "/v1/tunnels/tun_1/domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{Items: []api.TunnelDomain{domain}}})
		case "/v1/tunnels/tun_1/domains/domain_1/instructions":
			instructions := api.TunnelDNSInstructions{Schema: api.TunnelV1Schema, Kind: "dns_instructions", TunnelID: "tun_1", DomainID: "domain_1", Hostname: domain.Hostname, Provider: "generic", Records: []api.TunnelDNSRecord{{Name: domain.Hostname, Type: "CNAME", Value: "edge.example.test", TTL: 300}}, CertificateStrategy: "managed", VerificationState: "waiting_dns", Note: "Add this record."}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": instructions})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	})
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"domain", "instructions", "tun_1", "app.example.test"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "app.example.test\tCNAME\tedge.example.test\t300\nAdd this record.\n" {
		t.Fatalf("output=%q", output.String())
	}
}

func TestTunnelRouteMutationRetriesTransientFailureWithSameIdempotencyKey(t *testing.T) {
	oldDelay := tunnelRequestRetryDelay
	tunnelRequestRetryDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { tunnelRequestRetryDelay = oldDelay })
	var calls int
	var keys []string
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "temporarily_unavailable", "message": "control plane is retrying"}})
			return
		}
		route := validCommandRoute("route_1", "api")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: route, Operation: validCommandOperation("route", route.ID), Changed: true}})
	})
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"route", "add", "tun_1", "--name", "api", "--to", "http://127.0.0.1:8080"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("calls=%d keys=%v", calls, keys)
	}
}

func TestTunnelRouteMutationReportsTerminalFailureWithoutWait(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		route := validCommandRoute("route_1", "api")
		operation := validCommandOperation("route", route.ID)
		operation.Phase = "failed"
		operation.State = "failed"
		operation.Progress = 100
		operation.Error = &api.PreviewTunnelAPIError{Schema: api.TunnelV1Schema, Kind: "error", Code: "origin_unreachable", Component: "edge", Message: "origin unavailable", Outcome: "failed", RequestID: "request_1", CorrelationID: operation.CorrelationID}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{Route: route, Operation: operation, Changed: true}})
	})
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"route", "add", "tun_1", "--name", "api", "--to", "http://127.0.0.1:8080"})
	err := command.Execute()
	var outcome *TunnelOperationOutcomeError
	if !errors.As(err, &outcome) || outcome.Operation.State != "failed" || !strings.Contains(err.Error(), "operation operation_1") {
		t.Fatalf("error=%#v outcome=%#v", err, outcome)
	}
}

func TestTunnelRouteAddRejectsHTTPOverTCPOrigin(t *testing.T) {
	requests := 0
	withTunnelCommandClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	command := tunnelCobraCommandV1()
	command.SetArgs([]string{"route", "add", "tun_1", "--name", "api", "--to", "tcp://127.0.0.1:8080"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "HTTP routes cannot target a tcp origin") {
		t.Fatalf("error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("requests=%d", requests)
	}
}

type readyConnectorRecoveryWorkflow struct {
	journal   tunnelcreatejournal.Journal
	completed bool
}

func (w *readyConnectorRecoveryWorkflow) Snapshot() tunnelcreatejournal.Journal {
	return w.journal
}

func (w *readyConnectorRecoveryWorkflow) RecordTunnel(_ context.Context, tunnelID, operationID string) error {
	if tunnelID != w.journal.TunnelID || operationID != w.journal.OperationID {
		return tunnelcreatejournal.ErrRequestMismatch
	}
	return nil
}

func (w *readyConnectorRecoveryWorkflow) RecordConnectorReady(context.Context) error {
	return tunnelcreatejournal.ErrInvalid
}

func (w *readyConnectorRecoveryWorkflow) RecordDomain(_ context.Context, _ int, _ string) error {
	return tunnelcreatejournal.ErrInvalid
}

func (w *readyConnectorRecoveryWorkflow) Complete(context.Context) error {
	w.completed = true
	return nil
}

func (*readyConnectorRecoveryWorkflow) Close() error { return nil }

func TestTunnelCreateReadyConnectorJournalRecoversWithoutReenrollment(t *testing.T) {
	var requests []string
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tunnels":
			value := validCommandTunnel()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelMutation{Tunnel: value, Operation: validCommandOperation("tunnel", value.ID), Replayed: true}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tunnels/tun_1/connectors":
			readyAt := time.Unix(4, 0).UTC()
			connector := api.TunnelConnector{
				Schema: api.TunnelV1Schema, Kind: "connector", ID: "connector_1", TunnelID: "tun_1", HostID: "host_1",
				CredentialReference: "protected-file://paperboat/connector_1", RotationGeneration: 1, ProtocolVersion: "1.0",
				DesiredState: "active", DrainState: "accepting", Generation: 1, ETag: `"connector:connector_1:1"`, ReadyAt: &readyAt,
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelConnectorPage{Items: []api.TunnelConnector{connector}}})
		default:
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
	})
	workflow := &readyConnectorRecoveryWorkflow{}
	oldWorkflow := beginTunnelCreateWorkflowForCommand
	beginTunnelCreateWorkflowForCommand = func(_ context.Context, request tunnelCreateWorkflowRequest) (tunnelCreateWorkflow, error) {
		workflow.journal = tunnelcreatejournal.Journal{
			Schema: tunnelcreatejournal.Schema, HostID: "host_1", RequestDigest: request.RequestDigest, TunnelKey: "idem_test",
			TunnelID: "tun_1", OperationID: "operation_1", Stage: tunnelcreatejournal.StageConnectorReady,
			ExpiresAt: request.ExpiresAt, Domains: nil,
		}
		return workflow, nil
	}
	t.Cleanup(func() { beginTunnelCreateWorkflowForCommand = oldWorkflow })
	runtimeCalls := 0
	oldRuntime := tunnelConnectorAddRuntime
	tunnelConnectorAddRuntime = func(*cobra.Command, string) error {
		runtimeCalls++
		return errors.New("unexpected connector re-enrollment")
	}
	t.Cleanup(func() { tunnelConnectorAddRuntime = oldRuntime })
	var output bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&output)
	command.SetArgs([]string{"create", "demo", "--port", "8080", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if runtimeCalls != 0 || !workflow.completed {
		t.Fatalf("runtime calls=%d workflow completed=%v", runtimeCalls, workflow.completed)
	}
	if strings.Join(requests, ",") != "POST /v1/tunnels,GET /v1/tunnels/tun_1/connectors" {
		t.Fatalf("requests=%v", requests)
	}
	if !strings.Contains(output.String(), `"connector_id":"connector_1"`) || !strings.Contains(output.String(), `"replayed":true`) {
		t.Fatalf("output=%q", output.String())
	}
}

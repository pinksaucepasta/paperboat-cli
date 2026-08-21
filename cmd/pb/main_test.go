package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	bugreportpkg "github.com/pinksaucepasta/paperboat/internal/bugreport"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/command"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
	doctorpkg "github.com/pinksaucepasta/paperboat/internal/doctor"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/inbox"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"github.com/pinksaucepasta/paperboat/internal/localwait"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/identitybootstrap"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
	"github.com/pinksaucepasta/paperboat/internal/statusbar"
	"github.com/pinksaucepasta/paperboat/internal/telemetry"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
	"github.com/spf13/cobra"
)

func TestOpenSSHArgumentsPlacesRemoteCommandAfterDestination(t *testing.T) {
	destination := managedssh.Destination{User: "root", Host: "machine.pprbt", Port: 2222}
	got := openSSHArguments(destination, []string{"printf ssh-ok"}, true)
	want := []string{
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-p", "2222", "root@machine.pprbt", "printf ssh-ok",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("openSSHArguments() = %q, want %q", got, want)
	}
}

func TestResolveSSHRequestedUser(t *testing.T) {
	for _, test := range []struct{ target, flag, want string }{
		{target: "root", want: "root"},
		{flag: "deploy", want: "deploy"},
		{target: "root", flag: "root", want: "root"},
	} {
		got, err := resolveSSHRequestedUser(test.target, test.flag)
		if err != nil || got != test.want {
			t.Fatalf("resolveSSHRequestedUser(%q, %q) = %q, %v", test.target, test.flag, got, err)
		}
	}
	if _, err := resolveSSHRequestedUser("root", "deploy"); !errors.Is(err, managedssh.ErrSSHUsernameConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := resolveSSHRequestedUser("", "bad user"); !errors.Is(err, managedssh.ErrSSHUsernameInvalid) {
		t.Fatalf("invalid username error = %v", err)
	}
}

func TestPingCommandAndOutputContract(t *testing.T) {
	command, _, err := newRootCommand().Find([]string{"ping"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Use != "ping <machine>" || command.Flags().Lookup("count") == nil || command.Flags().Lookup("timeout") == nil || command.Flags().Lookup("json") == nil {
		t.Fatalf("unexpected ping command contract: %q", command.Use)
	}
	for path, want := range map[connectionmanager.Path]string{
		connectionmanager.PathDirectQUIC: "direct_quic",
		connectionmanager.PathRelayQUIC:  "relay_quic",
		connectionmanager.PathWSS:        "wss",
	} {
		if got := pingPath(path); got != want {
			t.Fatalf("pingPath(%d)=%q, want %q", path, got, want)
		}
	}
	report := pingReport{Schema: "paperboat.ping/v1", MachineID: "machine_01", MachineName: "workstation", Sent: 1, Received: 1, Samples: []pingSample{{Sequence: 1, Path: "relay_quic", RelayRegion: "bom", RTTMS: 12.5}}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"candidate", "endpoint", "address", "fingerprint", "credential", "token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("ping JSON exposed forbidden field category %q: %s", forbidden, encoded)
		}
	}
}

func TestUpdateCommandContract(t *testing.T) {
	root := newRootCommand()
	command, _, err := root.Find([]string{"update"})
	if err != nil || command == nil {
		t.Fatalf("find update: %v", err)
	}
	if command.Use != "update" || command.Flags().Lookup("json") == nil {
		t.Fatalf("unexpected update command contract: %q", command.Use)
	}
	for _, path := range [][]string{{"update", "check"}, {"update", "status"}} {
		child, _, childErr := root.Find(path)
		if childErr != nil || child == nil || child.Flags().Lookup("json") == nil {
			t.Fatalf("find %v: command=%v error=%v", path, child, childErr)
		}
	}
}

func TestPeerRacePolicyUsesOneSecondDirectPreference(t *testing.T) {
	policy := peerRacePolicy()
	if policy.RelayDelay != time.Second || policy.WSSDelay != time.Second || policy.ConnectTimeout != 20*time.Second {
		t.Fatalf("peer race policy=%+v", policy)
	}
}

func TestTransferAndPreviewCommandsDoNotExposeTransportSelection(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{{"send"}, {"preview", "create"}} {
		command, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		if command.Flags().Lookup("transport") != nil || command.Flags().Lookup("path") != nil {
			t.Fatalf("%v exposed a transport selector", path)
		}
	}
}

func TestPrivatePreviewTargetForcesDirectPeerTransport(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/machines/machine_1/preview-launch-descriptor" {
			http.NotFound(writer, request)
			return
		}
		writeAPIData(t, writer, api.PreviewLaunchDescriptor{
			Endpoint: "https://relay.example.test/v1/preview-launches", MachineID: "machine_1", ExpiresAt: expires,
			Auth: api.AuthMaterial{Method: "bearer", Token: "preview-token", ExpiresAt: expires, Scopes: []string{"preview:launch"}},
		})
	}))
	defer server.Close()
	client := api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client())
	target, err := privatePreviewPeerTarget(context.Background(), client, "machine_1", "machine", "environment_1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if target.Transport != string(tunnel.TerminalTransportDirect) || target.Terminal == nil || target.Terminal.Auth.Token != "preview-token" {
		t.Fatalf("target = %#v", target)
	}
}

func TestDoctorCommandAndOutputContract(t *testing.T) {
	command, _, err := newRootCommand().Find([]string{"doctor"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Use != "doctor [machine]" || command.Flags().Lookup("json") == nil {
		t.Fatalf("unexpected doctor command contract: %q", command.Use)
	}
	report := doctorpkg.Report{
		Schema: doctorpkg.SchemaV1, CorrelationID: "pb-doctor-0123456789abcdef", CheckedAt: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), Overall: "degraded",
		Machine: &doctorpkg.Machine{ID: "machine_01", Alias: "Studio"},
		Checks: []doctorpkg.Check{
			{Category: "transport", Code: "selected_path", Status: doctorpkg.StatusWarning, Summary: "The active Paperboat path uses a regional relay.", Recovery: "Direct connectivity is retried automatically."},
			{Category: "network", Code: "udp_ipv4", Status: doctorpkg.StatusPass, Summary: "IPv4 UDP sockets are available."},
		},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writeDoctorReport(&output, report)
	for _, expected := range []string{"Paperboat doctor: degraded", "Machine: Studio (machine_01)", "selected_path: warning", "Recovery:"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("doctor output %q does not contain %q", output.String(), expected)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"candidate", "endpoint", "fingerprint", "credential", "authorization", "token", "192.0.2."} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("doctor JSON exposed forbidden field category %q: %s", forbidden, encoded)
		}
	}
}

func TestDoctorMachineProbesReportReadinessWithoutSensitiveDetails(t *testing.T) {
	machine := localapi.MachineStatus{ID: "machine_1", Alias: "Studio", Eligible: true, RuntimeState: "ready", SelectedPath: "wss", RelayRegion: "bom", SSHReadiness: "degraded", NATMappingIPv4: "endpoint_independent", NATMappingIPv6: "destination_dependent", CaptivePortal: "suspected", PMTU: "standard", RouterProtocol: "pcp", RouterMapping: "verified", MappingLifetime: "30s_to_2m", UpdateHealth: "healthy"}
	probes := doctorMachineProbes(machine)
	checks := make(map[string]doctorpkg.Check, len(probes))
	for _, probe := range probes {
		checks[probe.Code] = probe.Run(context.Background())
	}
	if checks["machine_runtime"].Status != doctorpkg.StatusPass || checks["selected_path"].Status != doctorpkg.StatusWarning || checks["ssh_readiness"].Status != doctorpkg.StatusWarning || checks["nat_mapping_ipv4"].Status != doctorpkg.StatusPass || checks["nat_mapping_ipv6"].Status != doctorpkg.StatusWarning || checks["captive_portal"].Status != doctorpkg.StatusWarning || checks["path_mtu"].Status != doctorpkg.StatusPass || checks["router_protocol"].Status != doctorpkg.StatusPass || checks["router_mapping"].Status != doctorpkg.StatusPass || checks["mapping_lifetime"].Status != doctorpkg.StatusPass || checks["update_health"].Status != doctorpkg.StatusPass {
		t.Fatalf("checks=%#v", checks)
	}
	encoded, _ := json.Marshal(checks)
	if strings.Contains(string(encoded), "bom") {
		t.Fatalf("machine probes leaked relay detail outside the typed report: %s", encoded)
	}
}

func TestDoctorRouterProtocolCheckUsesOnlyBoundedCategories(t *testing.T) {
	for value, want := range map[string]string{
		"pcp": doctorpkg.StatusPass, "nat_pmp": doctorpkg.StatusPass, "upnp": doctorpkg.StatusPass,
		"none": doctorpkg.StatusUnavailable, "unknown": doctorpkg.StatusUnavailable,
	} {
		check := doctorRouterProtocolCheck(value)
		if check.Status != want || check.Code != "router_protocol" {
			t.Fatalf("value=%q check=%#v", value, check)
		}
		encoded, _ := json.Marshal(check)
		for _, forbidden := range []string{"192.0.2.1", "gateway address", "stun:", "external port", "device"} {
			if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
				t.Fatalf("value=%q leaked %q: %s", value, forbidden, encoded)
			}
		}
	}
}

func TestDoctorRouterMappingCheckUsesOnlyBoundedCategories(t *testing.T) {
	want := map[string]string{
		"verified":    doctorpkg.StatusPass,
		"unreachable": doctorpkg.StatusWarning,
		"untrusted":   doctorpkg.StatusUnavailable,
		"unavailable": doctorpkg.StatusUnavailable,
		"unknown":     doctorpkg.StatusUnavailable,
	}
	for value, status := range want {
		check := doctorRouterMappingCheck(value)
		if check.Status != status || check.Code != "router_mapping" {
			t.Fatalf("value=%q check=%#v", value, check)
		}
		encoded, _ := json.Marshal(check)
		for _, forbidden := range []string{"192.0.2.1", "stun:", "gateway", "pcp", "upnp", "nat-pmp"} {
			if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
				t.Fatalf("value=%q leaked %q: %s", value, forbidden, encoded)
			}
		}
	}
}

func TestDoctorMappingLifetimeCheckUsesConservativeBuckets(t *testing.T) {
	for value, want := range map[string]string{
		"over_10m":  doctorpkg.StatusPass,
		"2m_to_10m": doctorpkg.StatusPass,
		"30s_to_2m": doctorpkg.StatusPass,
		"under_30s": doctorpkg.StatusWarning,
		"unknown":   doctorpkg.StatusUnavailable,
	} {
		check := doctorMappingLifetimeCheck(value)
		if check.Status != want || check.Code != "mapping_lifetime" {
			t.Fatalf("value=%q check=%#v", value, check)
		}
	}
}

func TestDoctorPeerCheckClassifiesAuthenticatedPaths(t *testing.T) {
	for name, test := range map[string]struct {
		result   tunnel.PingResult
		status   string
		path     string
		fallback string
	}{
		"direct": {result: tunnel.PingResult{Path: connectionmanager.PathDirectQUIC, RTT: 8 * time.Millisecond}, status: doctorpkg.StatusPass, path: "direct", fallback: "none"},
		"relay":  {result: tunnel.PingResult{Path: connectionmanager.PathRelayQUIC, RelayRegion: "bom", RTT: 12 * time.Millisecond, PTOs: 1}, status: doctorpkg.StatusWarning, path: "relay", fallback: "direct_not_selected"},
		"wss":    {result: tunnel.PingResult{Path: connectionmanager.PathWSS, RelayRegion: "bom", RTT: 24 * time.Millisecond}, status: doctorpkg.StatusWarning, path: "wss", fallback: "quic_not_selected"},
	} {
		t.Run(name, func(t *testing.T) {
			check := doctorPeerCheck(test.result)
			if check.Status != test.status || check.SelectedPath != test.path || check.Fallback != test.fallback || check.RTTMS <= 0 {
				t.Fatalf("check=%#v", check)
			}
			if err := check.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDoctorIndependentPathChecksRequireAuthenticatedSuccess(t *testing.T) {
	pass := doctorPathReachabilityCheck("direct_reachability", "Direct QUIC", tunnel.PathReachability{Reachable: true, RTT: 8 * time.Millisecond})
	warning := doctorPathReachabilityCheck("relay_reachability", "Relay QUIC", tunnel.PathReachability{})
	if pass.Status != doctorpkg.StatusPass || pass.Recovery != "" || warning.Status != doctorpkg.StatusWarning || warning.Recovery == "" {
		t.Fatalf("pass=%#v warning=%#v", pass, warning)
	}
	encoded, _ := json.Marshal([]doctorpkg.Check{pass, warning})
	for _, forbidden := range []string{"endpoint", "candidate", "fingerprint", "192.0.2."} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("checks exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestShellCompletionIsBoundedSilentAndResourceSpecific(t *testing.T) {
	rootPath := t.TempDir()
	t.Setenv("HOME", rootPath)
	t.Setenv("XDG_STATE_HOME", filepath.Join(rootPath, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(rootPath, "runtime"))
	t.Setenv("TMPDIR", filepath.Join(rootPath, "runtime"))
	if err := os.MkdirAll(filepath.Join(rootPath, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := newRootCommand()
	for _, path := range [][]string{{"ping"}, {"wait"}, {"preview", "revoke"}, {"session", "attach"}, {"sessions", "delete"}} {
		command, _, err := root.Find(path)
		if err != nil || command.ValidArgsFunction == nil {
			t.Fatalf("completion hook missing for %v: %v", path, err)
		}
	}
	ping, _, _ := root.Find([]string{"ping"})
	started := time.Now()
	values, directive := ping.ValidArgsFunction(ping, nil, "ma")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("missing-daemon completion took %s", elapsed)
	}
	if len(values) != 0 || directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Fatalf("values=%v directive=%v", values, directive)
	}

	items := []api.TerminalSession{{ID: "session_02", Name: "worker", State: "running"}, {ID: "session_01", Name: "web", State: "stopped"}}
	got := sessionCompletionValues(items, "w")
	want := []string{"web\tstopped", "worker\trunning"}
	if !slices.Equal(got, want) {
		t.Fatalf("session completions=%v, want %v", got, want)
	}
	for _, value := range got {
		for _, forbidden := range []string{"token", "endpoint", "address", "fingerprint"} {
			if strings.Contains(strings.ToLower(value), forbidden) {
				t.Fatalf("completion exposed forbidden category %q: %q", forbidden, value)
			}
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func writeAPIData(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{"data": data}); err != nil {
		t.Fatal(err)
	}
}

func TestUserFacingErrorSanitizesInfrastructureFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		want   string
		forbid []string
	}{
		{
			name:   "network details",
			err:    fmt.Errorf("list projects: call GET /v1/projects: %w", &net.DNSError{Err: "no such host", Name: "api.secret.example"}),
			want:   "Paperboat is unreachable.",
			forbid: []string{"GET", "/v1/projects", "api.secret.example"},
		},
		{
			name: "operation deadline",
			err:  fmt.Errorf("peer stream setup: %w", context.DeadlineExceeded),
			want: "peer stream setup: context deadline exceeded",
		},
		{
			name:   "server outage",
			err:    &api.APIError{Status: http.StatusBadGateway, RequestID: "req_123"},
			want:   "Paperboat is temporarily unavailable.",
			forbid: []string{"status 502", "paperboat-server"},
		},
		{
			name:   "terminal loss",
			err:    errors.Join(tunnel.ErrTransportLost, errors.New("Application error 0x5042 (remote): server draining")),
			want:   "The terminal connection was lost",
			forbid: []string{"0x5042", "server draining", "transport lost"},
		},
		{
			name: "missing private transport custody",
			err:  config.ErrSecretNotFound,
			want: "not paired for private transport",
		},
		{
			name: "pairing required",
			err:  identitybootstrap.ErrPairingRequired,
			want: "needs the account recovery key",
		},
		{
			name:   "peer transport details",
			err:    fmt.Errorf("open machine: %w", &connectionmanager.Failure{Path: connectionmanager.PathRelayQUIC, Class: connectionmanager.FailureTransient, Cause: errors.New("read Noise response (prologue=secret fingerprint=private handle=private): E2EE authentication failed")}),
			want:   "secure connection could not be established",
			forbid: []string{"e2ee", "noise", "fingerprint", "handle", "secret", "connectionmanager", "peer path", "class"},
		},
		{
			name:   "peer deadline details",
			err:    fmt.Errorf("open machine: %w", &connectionmanager.Failure{Path: connectionmanager.PathRelayQUIC, Class: connectionmanager.FailureTransient, Cause: context.DeadlineExceeded}),
			want:   "secure connection could not be established",
			forbid: []string{"peer path", "class", "deadline exceeded"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := userFacingError(test.err)
			if !strings.Contains(got, test.want) {
				t.Fatalf("message = %q, want %q", got, test.want)
			}
			for _, forbidden := range test.forbid {
				if strings.Contains(got, forbidden) {
					t.Fatalf("message = %q contains %q", got, forbidden)
				}
			}
		})
	}
}

func TestRunTreatsCancellationAsUserCancellation(t *testing.T) {
	if got := userFacingError(context.Canceled); got != "Operation canceled." {
		t.Fatalf("message = %q", got)
	}
}

func TestRemoteExecCommandFormsReachExecutionInsteadOfTerminalUsage(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	for _, args := range [][]string{
		{"--config", configPath, "Studio", "--", "/bin/echo", "hello world"},
		{"--config", configPath, "exec", "Studio", "--env", "VALUE=hello world", "--", "/bin/echo", "hello world"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code == 2 {
			t.Fatalf("args=%v treated as usage error: %s", args, stderr.String())
		}
	}
}

func TestWriteExecJSONFailure(t *testing.T) {
	var output bytes.Buffer
	if err := writeExecJSONFailure(&output, "exec-operation-1", "exec_start_uncertain", "root cause", true, true); err != nil {
		t.Fatal(err)
	}
	var event struct {
		Version     string `json:"version"`
		Event       string `json:"event"`
		OperationID string `json:"operation_id"`
		ErrorCode   string `json:"error_code"`
		Changed     bool   `json:"changed"`
		Uncertain   bool   `json:"uncertain"`
	}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Version != "paperboat.exec-event/v1" || event.Event != "failed" || event.OperationID != "exec-operation-1" || event.ErrorCode != "exec_start_uncertain" || !event.Changed || !event.Uncertain {
		t.Fatalf("event = %#v", event)
	}
}

func TestExecConnectInfoPreservesRequestedPath(t *testing.T) {
	machine := api.UserMachine{ID: "machine_1", DisplayName: "host", InstallationGeneration: 2}
	descriptor := api.ExecDescriptor{Environment: &api.Environment{ID: "environment_1", Root: "/root"}}
	info := execConnectInfo(machine, descriptor, "q")
	if info.Transport != "q" {
		t.Fatalf("transport = %q, want q", info.Transport)
	}
}

type execInputTestConn struct {
	mu         sync.Mutex
	writes     [][]byte
	writeErr   error
	closeWrite bool
}

func (c *execInputTestConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *execInputTestConn) Close() error                    { return nil }
func (c *execInputTestConn) Detach() error                   { return nil }
func (c *execInputTestConn) Resize(uint16, uint16) error     { return nil }
func (c *execInputTestConn) Signal(string) error             { return nil }
func (c *execInputTestConn) Cancel() error                   { return nil }
func (c *execInputTestConn) Wait() (int, error)              { return 0, nil }
func (c *execInputTestConn) Events() <-chan tunnel.ExecEvent { return make(chan tunnel.ExecEvent) }
func (c *execInputTestConn) Write(value []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), value...))
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(value), nil
}
func (c *execInputTestConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWrite = true
	c.mu.Unlock()
	return nil
}

type sshProxyTestConn struct {
	net.Conn
	closeWrite func() error
}

func (c *sshProxyTestConn) CloseWrite() error { return c.closeWrite() }

type sshProxyCopyFailureConn struct {
	err    error
	failed chan struct{}
	once   sync.Once
}

func (c *sshProxyCopyFailureConn) Read([]byte) (int, error) { <-c.failed; return 0, io.EOF }
func (c *sshProxyCopyFailureConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.failed) })
	return 0, c.err
}
func (*sshProxyCopyFailureConn) Close() error      { return nil }
func (*sshProxyCopyFailureConn) CloseWrite() error { return net.ErrClosed }

func TestCopySSHProxyRemoteEOFTerminatesWithOpenInput(t *testing.T) {
	proxy, remote := net.Pipe()
	inputReader, inputWriter := io.Pipe()
	defer inputWriter.Close()
	defer inputReader.Close()
	connection := &sshProxyTestConn{Conn: proxy, closeWrite: func() error { return nil }}
	done := make(chan error, 1)
	go func() { done <- copySSHProxy(connection, connection, inputReader, io.Discard) }()
	_ = remote.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH proxy waited for input after remote EOF")
	}
}

func TestCopySSHProxyInputEOFHalfClosesAndDrainsOutput(t *testing.T) {
	proxy, remote := net.Pipe()
	halfClosed := make(chan struct{})
	connection := &sshProxyTestConn{Conn: proxy, closeWrite: func() error {
		close(halfClosed)
		return nil
	}}
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- copySSHProxy(connection, connection, strings.NewReader("request"), &output) }()
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(remote, request); err != nil || string(request) != "request" {
		t.Fatalf("request=%q err=%v", request, err)
	}
	select {
	case <-halfClosed:
	case <-time.After(time.Second):
		t.Fatal("input EOF did not half-close SSH stream")
	}
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	if err := <-done; err != nil || output.String() != "response" {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
}

func TestCopySSHProxyRemoteEOFIgnoresConcurrentClosedHalfClose(t *testing.T) {
	for _, closeErr := range []error{net.ErrClosed, io.ErrClosedPipe, &net.OpError{Op: "shutdown", Net: "unix", Err: syscall.ENOTCONN}} {
		for range 100 {
			proxy, remote := net.Pipe()
			connection := &sshProxyTestConn{Conn: proxy, closeWrite: func() error { return closeErr }}
			done := make(chan error, 1)
			go func() { done <- copySSHProxy(connection, connection, strings.NewReader("request"), io.Discard) }()
			request := make([]byte, len("request"))
			if _, err := io.ReadFull(remote, request); err != nil {
				t.Fatal(err)
			}
			_ = remote.Close()
			if err := <-done; err != nil {
				t.Fatalf("clean remote EOF returned half-close error: %v", err)
			}
		}
	}
}

func TestCopySSHProxyRemoteEOFPreservesInputCopyFailure(t *testing.T) {
	connection := &sshProxyCopyFailureConn{err: tunnel.ErrTransportLost, failed: make(chan struct{})}
	err := copySSHProxy(connection, connection, strings.NewReader("request"), io.Discard)
	if !errors.Is(err, tunnel.ErrTransportLost) {
		t.Fatalf("error=%v, want transport loss", err)
	}
}

type execChunkReader struct {
	chunks [][]byte
	index  int
}

func (r *execChunkReader) Read(value []byte) (int, error) {
	if r.index == len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	r.index++
	return copy(value, chunk), nil
}

func TestForwardExecInputSwitchesConnectionsWithoutReplayingUncertainChunk(t *testing.T) {
	first := &execInputTestConn{writeErr: tunnel.ErrTransportLost}
	second := &execInputTestConn{}
	connections := newExecConnectionRef(first)
	done := make(chan struct{})
	go func() {
		forwardExecInput(context.Background(), &execChunkReader{chunks: [][]byte{[]byte("uncertain"), []byte("next")}}, connections)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for connections.Current() != nil {
		if time.Now().After(deadline) {
			t.Fatal("failed connection was not cleared")
		}
		time.Sleep(time.Millisecond)
	}
	if err := connections.Set(second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("input forwarding did not finish")
	}
	if len(first.writes) != 1 || string(first.writes[0]) != "uncertain" {
		t.Fatalf("first writes = %q", first.writes)
	}
	if len(second.writes) != 1 || string(second.writes[0]) != "next" || !second.closeWrite {
		t.Fatalf("second writes = %q closeWrite=%v", second.writes, second.closeWrite)
	}
}

func TestFinishExecResultReservedExitCodesAndJSONTransportFailure(t *testing.T) {
	for name, test := range map[string]struct {
		code         int
		err          error
		sawTerminal  bool
		wantExit     int
		wantJSONCode string
	}{
		"remote exit":       {code: 37, wantExit: 37, sawTerminal: true},
		"timeout":           {err: &tunnel.RemoteExecError{Code: "exec_timeout"}, wantExit: 124, sawTerminal: true},
		"cancel":            {err: &tunnel.RemoteExecError{Code: "exec_canceled"}, wantExit: 130, sawTerminal: true},
		"remote failure":    {err: &tunnel.RemoteExecError{Code: "exec_result_unavailable"}, wantExit: 125, sawTerminal: true},
		"transport failure": {err: tunnel.ErrTransportLost, wantExit: 255, wantJSONCode: "transport_lost"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := finishExecResult(&stdout, &stderr, "exec-operation-1", true, test.sawTerminal, test.code, test.err)
			var exit interface{ ExitCode() int }
			if !errors.As(err, &exit) || exit.ExitCode() != test.wantExit {
				t.Fatalf("error=%v exit=%v, want %d", err, exit, test.wantExit)
			}
			if stderr.Len() != 0 {
				t.Fatalf("JSON mode wrote stderr: %q", stderr.String())
			}
			if test.wantJSONCode == "" {
				if stdout.Len() != 0 {
					t.Fatalf("unexpected JSON: %q", stdout.String())
				}
				return
			}
			var event struct {
				Event     string `json:"event"`
				ErrorCode string `json:"error_code"`
				Changed   bool   `json:"changed"`
				Uncertain bool   `json:"uncertain"`
			}
			if json.Unmarshal(stdout.Bytes(), &event) != nil || event.Event != "failed" || event.ErrorCode != test.wantJSONCode || !event.Changed || !event.Uncertain {
				t.Fatalf("event=%#v output=%q", event, stdout.String())
			}
		})
	}
}

func TestExecEventNameReportsSignalTerminalEvent(t *testing.T) {
	event := tunnel.ExecEvent{State: "exited", Result: &tunnel.ExecResult{Signal: "SIGTERM"}}
	if got := execEventName(event); got != "signaled" {
		t.Fatalf("event name = %q", got)
	}
	changed := execEventChanged(event)
	if changed == nil || !*changed {
		t.Fatalf("changed = %v", changed)
	}
}

func TestCollectLocalDoctorDoesNotCreateUnconfiguredIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-state")
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", root)
	report := collectLocalDoctor()
	if report.SetupState != "not_set_up" || report.IdentityState != "missing" || !slices.Contains(report.RecoveryActions, "run pb setup") {
		t.Fatalf("report=%+v", report)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor mutated unconfigured state: %v", err)
	}
}

func TestCollectLocalDoctorReportsMachineInboxCredentialAndPreviews(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", root)
	store, err := identity.Open(identity.Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(root, "Paperboat Inbox")
	if err := inbox.EnsurePath(inboxPath); err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := identity.Registration{ServerURL: "https://api.example.test", MachineID: "machine_local", EnvironmentID: "env_local", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: inboxPath, InstallationGeneration: 4, SetupRoles: []string{"interactive", "host"}, UpdatedAt: time.Now().UTC()}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMachineControl(identity.MachineControl{MachineID: registration.MachineID, EnvironmentID: registration.EnvironmentID, InstallationGeneration: registration.InstallationGeneration, Credential: strings.Repeat("x", 32), ExpiresAt: time.Now().UTC().Add(time.Hour), KeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	descriptor, _ := json.Marshal(map[string]any{"schema": "paperboat.preview-runtime/v1", "name": "docs", "port": 3000, "indefinite": false, "expires_at": expires, "service_definition": ""})
	if err := os.WriteFile(filepath.Join(active, "docs.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	report := collectLocalDoctor()
	if report.SetupState != "configured" || report.IdentityState != "valid" || report.MachineID != "machine_local" || report.InstallationGeneration != 4 || !slices.Equal(report.SetupRoles, []string{"interactive", "host"}) || report.InboxState != "ready" || report.CredentialState != "valid" || report.ActivePreviews != 1 || report.InvalidPreviews != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestDoctorValidatesServedPreviewSourceWithoutReportingPath(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "site")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	source, _ := servepkg.ResolveSource(sourcePath)
	identityValue, _ := source.Identity()
	expires := time.Now().UTC().Add(time.Hour)
	descriptor, _ := json.Marshal(map[string]any{
		"schema": "paperboat.preview-runtime/v1", "name": "site", "bind_address": "127.0.0.1", "port": 32000, "service_generation": 1, "indefinite": false, "expires_at": expires, "service_definition": "",
		"serve": map[string]any{"source_path": source.Path, "source_kind": source.Kind, "source_identity": identityValue, "spa": false, "owner_mode": "detached", "visibility": "private"},
	})
	directory := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "site.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	report := localDoctorReport{}
	inspectLocalPreviewDescriptors(&report, directory, time.Now().UTC())
	if report.ActivePreviews != 1 || report.ServedPreviews != 1 || report.InvalidPreviews != 0 || report.InvalidServeSources != 0 {
		t.Fatalf("report = %#v", report)
	}
	encoded, _ := json.Marshal(report)
	if bytes.Contains(encoded, []byte(source.Path)) {
		t.Fatalf("doctor leaked source path: %s", encoded)
	}
}

func TestDoctorAcceptsPrivateRemotePreviewDescriptor(t *testing.T) {
	root := t.TempDir()
	expires := time.Now().UTC().Add(time.Hour)
	descriptor, _ := json.Marshal(map[string]any{
		"schema": "paperboat.preview-runtime/v1", "name": "remote", "bind_address": "127.0.0.1", "port": 32000, "service_generation": 7, "indefinite": false, "expires_at": expires, "service_definition": filepath.Join(root, "remote.service"),
		"record":         map[string]any{"logical_name": "remote", "url": "http://127.0.0.1:32000", "target_port": 38142, "state": "ready", "expires_at": expires},
		"private_remote": map[string]any{"machine_id": "machine_1", "machine_name": "Hetzner", "environment_id": "environment_1", "machine_generation": 4, "target_port": 38142, "listen_port": 32000},
	})
	directory := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "remote.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	report := localDoctorReport{}
	inspectLocalPreviewDescriptors(&report, directory, time.Now().UTC())
	if report.ActivePreviews != 1 || report.InvalidPreviews != 0 || report.ServedPreviews != 0 {
		t.Fatalf("report=%#v", report)
	}
}

func TestDoctorComparesServedRoutesWithLocalWorkloads(t *testing.T) {
	report := localDoctorReport{MachineID: "machine_local", ActiveServedPreviews: 1, RuntimeForegroundServes: 1}
	compareLocalServedPreviewRoutes(&report, []api.Preview{
		{ID: "detached", ResourceID: "machine_local", SourceKind: "directory", State: "ready"},
		{ID: "foreground", ResourceID: "machine_local", SourceKind: "file", State: "ready"},
		{ID: "other", ResourceID: "machine_other", SourceKind: "file", State: "ready"},
	})
	if report.RouteReadiness != "ready" || report.RemoteServedPreviews != 2 {
		t.Fatalf("report=%+v", report)
	}
	report = localDoctorReport{MachineID: "machine_local", ActiveServedPreviews: 1}
	compareLocalServedPreviewRoutes(&report, []api.Preview{{ID: "orphan", ResourceID: "machine_local", SourceKind: "file", State: "ready"}, {ID: "orphan2", ResourceID: "machine_local", SourceKind: "file", State: "ready"}})
	if report.RouteReadiness != "workload_route_drift" || len(report.RecoveryActions) == 0 {
		t.Fatalf("drift report=%+v", report)
	}
}

func TestHostRuntimeEntryPointIsHiddenAndStrict(t *testing.T) {
	root := newRootCommand()
	command, _, err := root.Find([]string{"__runtime-host"})
	if err != nil || command == nil || !command.Hidden {
		t.Fatalf("runtime command = %#v, %v", command, err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"__runtime-host", "extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 || strings.Contains(stdout.String(), "__runtime-host") {
		t.Fatalf("help exposed runtime command: code=%d output=%q", code, stdout.String())
	}
}

func TestConnectTelemetryFailsOpenWithWarning(t *testing.T) {
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Observability: config.ObservabilityConfig{EventLogPath: filepath.Join(blockedParent, "telemetry.jsonl")}}
	var warnings bytes.Buffer
	sink, closeSink := connectTelemetry(cfg, &warnings)
	defer closeSink()
	if _, ok := sink.(telemetry.NopSink); !ok {
		t.Fatalf("sink type = %T, want telemetry.NopSink", sink)
	}
	if warnings.String() != "warning: telemetry disabled: local event log unavailable\n" {
		t.Fatalf("warning = %q", warnings.String())
	}
}

func TestRetryableInitialConnectError(t *testing.T) {
	if retryableInitialConnectError(fmt.Errorf("connect to project: %w", resolver.ErrProjectNotFound)) {
		t.Fatal("project lookup failure must not retry")
	}
	if !retryableInitialConnectError(&api.APIError{Code: "machine_not_ready"}) {
		t.Fatal("machine_not_ready should retry")
	}
}

func TestSelectTerminalSessionDoesNotHideAmbiguousProjectWithUserMachine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"items":[{"id":"prj_1","name":"studio"},{"id":"prj_2","name":"Studio"}],"pagination":{"next_offset":null}}}`))
		case "/v1/machines":
			t.Fatal("machine lookup must not hide an ambiguous project name")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, _, _, err := selectTerminalSession(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "studio", "", "named")
	if !errors.Is(err, resolver.ErrProjectAmbiguous) {
		t.Fatalf("err = %v, want project ambiguity", err)
	}
}

func TestSelectTerminalSessionCreatesFreshSessionByDefault(t *testing.T) {
	created := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "studio", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			created = true
			writeAPIData(t, w, map[string]any{"id": "pts_1", "name": "quiet-harbor", "state": "open", "created_at": time.Now(), "updated_at": time.Now()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, _, _, err := selectTerminalSession(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "studio", "", "")
	if err != nil || got.ID != "pts_1" || got.Name != "quiet-harbor" || !created {
		t.Fatalf("fresh session = %+v, %v; created=%t", got, err, created)
	}
}

func TestTerminalArgsAcceptsOnlyOptionalNewKeyword(t *testing.T) {
	validate := terminalArgs(0)
	for _, values := range [][]string{nil, {"studio"}, {"studio", "new"}} {
		if err := validate(nil, values); err != nil {
			t.Fatalf("values %q rejected: %v", values, err)
		}
	}
	if err := validate(nil, []string{"studio", "attach"}); err == nil {
		t.Fatal("unexpected second keyword accepted")
	}
}

type refreshTestAuth struct {
	current   config.Credential
	refreshed config.Credential
	refreshes int
}

func (a *refreshTestAuth) Credential() (config.Credential, error) { return a.current, nil }
func (a *refreshTestAuth) Refresh() (config.Credential, error) {
	a.refreshes++
	return a.refreshed, nil
}

func TestPollConfigSyncUsesAttachedProjectState(t *testing.T) {
	requested := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("request = %s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/config-sync/status":
			_, _ = w.Write([]byte(`{"data":{"state":"healthy","environments":[{"environment_id":"other","state":"healthy","mode":"pull_only","manifest_health":"empty"},{"environment_id":"attached","state":"warning","mode":"bidirectional","manifest_health":"healthy","managed_path_count":2,"pending_clean_path_count":1}]}}`))
			requested <- struct{}{}
		case "/v1/usage-summary":
			_, _ = w.Write([]byte(`{"data":{"credits":{"balance":"100.000000"},"storage":{"available_gb":12}}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	outputReader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputReader.Close()
	bar := statusbar.New(statusbar.Options{
		Mode:           statusbar.ModeAuto,
		Term:           "xterm-256color",
		NoticeDuration: time.Second,
		Input:          input,
		Output:         output,
		IsTerminal:     func(int) bool { return true },
		GetSize:        func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("config-sync poll was not requested")
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync needs attention") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync needs attention") {
		t.Fatalf("attached environment state was not selected: %q", got)
	}
	deadline = time.Now().Add(time.Second)
	for !strings.Contains(bar.Render(80), "credits 100") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Render(80); !strings.Contains(got, "credits 100") {
		t.Fatalf("usage summary was not rendered: %q", got)
	}
	cancel()
	<-done
	_ = bar.Close()
	_ = output.Close()
	raw, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Config sync needs attention") || !strings.Contains(string(raw), "credits 100") {
		t.Fatalf("status/usage were not rendered: %q", raw)
	}
}

func TestPollConfigSyncWaitsForAttachedProjectStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"state":"healthy","projects":[]}}`))
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	_, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	bar := statusbar.New(statusbar.Options{
		Mode: statusbar.ModeAuto, Term: "xterm-256color", NoticeDuration: time.Second,
		Input: input, Output: output, IsTerminal: func(int) bool { return true },
		GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync awaiting status") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync awaiting status") || strings.Contains(got, "unavailable") {
		t.Fatalf("missing-project status = %q", got)
	}
	cancel()
	<-done
}

func TestPollConfigSyncKeepsAuthenticationFailuresVisible(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"Authentication is required."}}`))
	}))
	defer server.Close()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	_, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	bar := statusbar.New(statusbar.Options{
		Mode: statusbar.ModeAuto, Term: "xterm-256color", NoticeDuration: time.Second,
		Input: input, Output: output, IsTerminal: func(int) bool { return true },
		GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollConfigSync(ctx, server.URL, &refreshTestAuth{current: config.Credential{AccessToken: "token"}}, "attached", time.Hour, bar)
		close(done)
	}()
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("config-sync request was not sent")
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(bar.Text(), "Config sync status unavailable") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bar.Text(); !strings.Contains(got, "Config sync status unavailable") {
		t.Fatalf("authentication failure was hidden: %q", got)
	}
	cancel()
	<-done
}

func TestFormatStatusCredits(t *testing.T) {
	for raw, want := range map[string]string{
		"100":        "100",
		"100.000000": "100",
		"0.000000":   "0",
		"12.340000":  "12.34",
	} {
		if got := formatStatusCredits(raw); got != want {
			t.Fatalf("formatStatusCredits(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestConnectWithServerURLUsesBackendResolver(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "runtime")
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
	identityStore, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(dir, "Paperboat Inbox")
	if err := os.MkdirAll(inboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.SaveRegistration(identity.Registration{ServerURL: "https://api.example.test", MachineID: "machine_source", EnvironmentID: "env_source", PublicKeyID: identityStore.Current().ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityStore.Current().Public()), InboxPath: inboxPath, InstallationGeneration: 1, SetupRoles: []string{"interactive"}, UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	var sawProjects bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/projects" {
			sawProjects = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"items":[],"pagination":{"limit":200,"offset":0,"total":0,"next_offset":null}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	writeTestProfile(t, dir, configPath, server.URL)

	err = newApp().Run([]string{"pb", "--config", configPath, "--server", server.URL, "demo"})
	if err == nil {
		t.Fatal("expected project lookup error")
	}
	if !sawProjects {
		t.Fatal("expected backend project list request")
	}
	if !strings.Contains(err.Error(), "project not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestHelpCommandDoesNotCallBackend(t *testing.T) {
	var output bytes.Buffer
	app := newApp()
	app.Writer = &output
	app.ErrWriter = &output
	if err := app.Run([]string{"pb", "help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Usage:") || !strings.Contains(output.String(), "Available Commands:") {
		t.Fatalf("help output = %q", output.String())
	}
}

func TestVersionFlags(t *testing.T) {
	previous := buildinfo.Version
	buildinfo.Version = "2026.07.25.0"
	t.Cleanup(func() { buildinfo.Version = previous })
	for _, flag := range []string{"--version", "-v"} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{flag}, &stdout, &stderr); code != 0 || stdout.String() != versionDisplay("2026.07.25.0") || stderr.Len() != 0 {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", flag, code, stdout.String(), stderr.String())
		}
	}
}

func TestPeerConnectionModePreservesConfiguredTransport(t *testing.T) {
	for _, test := range []struct {
		terminal tunnel.TerminalTransport
		peer     connectionmanager.Mode
	}{
		{terminal: tunnel.TerminalTransportAuto, peer: connectionmanager.ModeAuto},
		{terminal: tunnel.TerminalTransportDirect, peer: connectionmanager.ModeDirectQUIC},
		{terminal: tunnel.TerminalTransportRelayWSS, peer: connectionmanager.ModeWSS},
		{terminal: tunnel.TerminalTransportRelayQUIC, peer: connectionmanager.ModeRelayQUIC},
		{terminal: tunnel.TerminalTransportRelay, peer: connectionmanager.ModeRelayRace},
	} {
		if got := peerConnectionMode(test.terminal); got != test.peer {
			t.Fatalf("terminal mode=%q peer mode=%d want=%d", test.terminal, got, test.peer)
		}
	}
}

func TestVersionDisplayIncludesBrandAndVersion(t *testing.T) {
	display := versionDisplay("2026.08.02.0")
	if !strings.Contains(display, "Paperboat") || !strings.Contains(display, "Version 2026.08.02.0") {
		t.Fatalf("version display = %q", display)
	}
}

func TestBrandDisplayAlignsMetadataByTerminalCellWidth(t *testing.T) {
	display := brandDisplay("2026.08.02.0", "person@example.com")
	details := []string{"Paperboat", "Version 2026.08.02.0", "person@example.com"}
	lines := strings.Split(display, "\n")
	if len(lines) != len(details) {
		t.Fatalf("brand lines = %q", lines)
	}
	column := -1
	for index, detail := range details {
		position := strings.Index(lines[index], detail)
		if position < 0 {
			t.Fatalf("line %d missing %q: %q", index, detail, lines[index])
		}
		cell := ansi.StringWidth(lines[index][:position])
		if column < 0 {
			column = cell
		} else if cell != column {
			t.Fatalf("line %d metadata column = %d, want %d: %q", index, cell, column, lines[index])
		}
	}
}

func TestUpdateSelectedTransportUsesSelectorOutcome(t *testing.T) {
	bar := statusbar.New(statusbar.Options{
		Mode:   statusbar.ModeOff,
		Layout: statusbar.Layout{Right: []string{"connection"}},
	})
	bar.SetConnection("connected")

	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "quic"}, "selected")
	if line := bar.Render(40); !strings.Contains(line, "connected  q") {
		t.Fatalf("selected QUIC transport missing from status bar: %q", line)
	}
	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "wss"}, "selected")
	if line := bar.Render(40); !strings.Contains(line, "connected  w") {
		t.Fatalf("selected WSS transport missing from status bar: %q", line)
	}
	updateSelectedTransport(bar, tunnel.TerminalTransportSelection{Selected: "quic"}, "failure")
	if line := bar.Render(40); !strings.Contains(line, "connected  w") {
		t.Fatalf("failed selection changed status bar transport: %q", line)
	}
}

func TestMachineTransportSnapshotCannotOverwriteForcedStatusBarMarker(t *testing.T) {
	bar := statusbar.New(statusbar.Options{Mode: statusbar.ModeOff, Layout: statusbar.Layout{Right: []string{"connection"}}})
	bar.SetConnection("connected")
	snapshot := localapi.Snapshot{Machines: []localapi.MachineStatus{{ID: "machine_1", SelectedPath: "mixed", ActiveConsumers: 2, TransportConsumers: []localapi.TransportConsumer{{Path: "direct", ActiveConsumers: 1}, {Path: "relay", ActiveConsumers: 1, RelayRegion: "bom"}}}}}
	applyMachineTransportPath(snapshot, "machine_1", tunnel.TerminalTransportDirect, bar)
	if line := bar.Render(40); !strings.Contains(line, "connected  d") {
		t.Fatalf("forced direct marker overwritten: %q", line)
	}
}

func TestMachineTransportSnapshotRetainsAutoMarkerForMixedPaths(t *testing.T) {
	bar := statusbar.New(statusbar.Options{Mode: statusbar.ModeOff, Layout: statusbar.Layout{Right: []string{"connection"}}})
	bar.SetConnection("connected")
	applyMachineTransportPath(localapi.Snapshot{Machines: []localapi.MachineStatus{{ID: "machine_1", SelectedPath: "relay"}}}, "machine_1", tunnel.TerminalTransportAuto, bar)
	applyMachineTransportPath(localapi.Snapshot{Machines: []localapi.MachineStatus{{ID: "machine_1", SelectedPath: "mixed", ActiveConsumers: 2, TransportConsumers: []localapi.TransportConsumer{{Path: "direct", ActiveConsumers: 1}, {Path: "relay", ActiveConsumers: 1, RelayRegion: "bom"}}}}}, "machine_1", tunnel.TerminalTransportAuto, bar)
	if line := bar.Render(40); !strings.Contains(line, "connected  q") {
		t.Fatalf("mixed aggregate erased automatic marker: %q", line)
	}
}

func TestCanonicalCommandsAreDiscoverable(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{{"login"}, {"logout"}, {"pair"}, {"session", "attach"}, {"session", "list"}, {"machine", "add"}, {"machine", "list"}, {"machine", "rename"}, {"machine", "revoke"}, {"machine", "availability"}, {"preview", "list"}, {"preview", "revoke"}} {
		command, remaining, err := root.Find(path)
		if err != nil || len(remaining) != 0 || command == root {
			t.Fatalf("command %q not discoverable: command=%v remaining=%q err=%v", path, command, remaining, err)
		}
	}
	for _, removed := range []string{"create", "projects"} {
		command, remaining, err := root.Find([]string{removed})
		if err != nil || command != root || len(remaining) != 1 {
			t.Fatalf("removed command %q is still discoverable: command=%v remaining=%q err=%v", removed, command, remaining, err)
		}
	}
}

func TestMachineSessionActivityUsesNewestAvailableTimestamp(t *testing.T) {
	created := time.Unix(10, 0)
	updated := time.Unix(20, 0)
	active := time.Unix(30, 0)
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created, UpdatedAt: updated, LastActiveAt: &active}}).activity(); !got.Equal(active) {
		t.Fatalf("activity=%v want=%v", got, active)
	}
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created, UpdatedAt: updated}}).activity(); !got.Equal(updated) {
		t.Fatalf("activity=%v want=%v", got, updated)
	}
	if got := (machineSession{session: api.TerminalSession{CreatedAt: created}}).activity(); !got.Equal(created) {
		t.Fatalf("activity=%v want=%v", got, created)
	}
}

func TestFavoritesSortFirstWithoutReorderingPeers(t *testing.T) {
	values := []struct {
		id       string
		favorite bool
	}{{"first", false}, {"star-a", true}, {"second", false}, {"star-b", true}}
	slices.SortStableFunc(values, func(a, b struct {
		id       string
		favorite bool
	}) int {
		return compareFavorites(a.favorite, b.favorite)
	})
	got := make([]string, 0, len(values))
	for _, value := range values {
		got = append(got, value.id)
	}
	if strings.Join(got, ",") != "star-a,star-b,first,second" {
		t.Fatalf("order=%v", got)
	}
}

func TestMaskEmailHidesAddressUntilExplicitReveal(t *testing.T) {
	if got := maskEmail("person@example.com"); got != "██████@███████.███" {
		t.Fatalf("masked email=%q", got)
	}
	if got := maskEmail("Not signed in"); got != "Not signed in" {
		t.Fatalf("non-email=%q", got)
	}
}

func TestMachineAvailabilityRequiresConfirmationAndReturnsAppliedJSON(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"machine", "availability", "um_1", "--mode", "keep-awake"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("confirmation error=%v", err)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio", "availability": map[string]any{"schema": "paperboat.availability-policy/v1", "desired_mode": "allow_sleep", "desired_version": 3, "observed_version": 3, "status": "applied"}}}, "pagination": map[string]any{"next_offset": nil}})
		case "PUT /v1/machines/um_1/availability-policy":
			if r.Header.Get("Idempotency-Key") == "" {
				t.Fatal("missing idempotency key")
			}
			writeAPIData(t, w, map[string]any{"schema": "paperboat.availability-policy/v1", "desired_mode": "keep_awake", "desired_version": 4, "observed_mode": "keep_awake", "observed_version": 4, "status": "applied", "observed_at": "2026-07-26T12:00:00Z", "host_service_version": "test", "host_service_scope": "system"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "availability", "Studio", "--mode", "keep-awake", "--yes", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var output struct {
		Version      string                 `json:"version"`
		Outcome      string                 `json:"outcome"`
		Retry        string                 `json:"retry"`
		Availability api.AvailabilityPolicy `json:"availability"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output.Version != "1" || output.Outcome != "applied" || output.Retry != "automatic" || output.Availability.DesiredVersion != 4 {
		t.Fatalf("output=%q decoded=%+v err=%v", stdout.String(), output, err)
	}
	if !strings.Contains(stderr.String(), "Machine: Studio (um_1)") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestMachineRevokeRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"machine", "revoke", "um_1"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v, want confirmation error", err)
	}
}

func TestPreviewRevokeDisplaysResolvedContextBeforeConfirmation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected mutation before confirmation: %s %s", r.Method, r.URL.Path)
		}
		writeAPIData(t, w, []map[string]any{{"id": "prv_1", "environment_id": "env_1", "project_id": "prj_1", "resource_id": "um_1", "user_id": "usr_1", "logical_name": "web", "environment_name": "studio", "environment_kind": "byod", "owner_email": "owner@example.test", "url": "https://preview.example.test", "state": "ready", "target_port": 3000}})
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--config", configPath, "preview", "revoke", "prv_1"}, &bytes.Buffer{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "Preview: web (studio, byod)") || !strings.Contains(stderr.String(), "Project: prj_1  Resource: um_1  User: usr_1") || len(requests) != 1 {
		t.Fatalf("code=%d stderr=%q requests=%v", code, stderr.String(), requests)
	}
}

func TestSessionCloseRequiresConfirmationBeforeBackend(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"session", "close", "um_1", "shell-2"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v, want confirmation error", err)
	}
}

func TestSessionCloseAllRequiresConfirmationAndRejectsSessionArgument(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	mutated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}}, "pagination": map[string]any{"next_offset": nil}})
		default:
			mutated = true
			t.Fatalf("unexpected request before confirmation: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "sessions", "close", "demo", "--all"}, &output, &output); code != 1 || mutated || !strings.Contains(output.String(), "Environment: demo (prj_1)") || !strings.Contains(output.String(), "Open sessions to close: 1") || !strings.Contains(output.String(), "requires --yes") {
		t.Fatalf("code=%d mutated=%t output=%q", code, mutated, output.String())
	}

	root := newRootCommand()
	root.SetArgs([]string{"session", "close", "um_1", "shell-2", "--all", "--yes"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "usage: pb session close") {
		t.Fatalf("err=%v, want mutually exclusive usage error", err)
	}
}

func TestSessionCloseAllClosesEveryOpenSession(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}, {"id": "ses_2", "name": "api", "state": "open"}, {"id": "ses_3", "name": "old", "state": "closed"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/close"):
			closed = append(closed, r.URL.Path)
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "session", "close", "demo", "--all", "--yes"}, &output, &output); code != 0 {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
	if len(closed) != 2 || !strings.Contains(closed[0], "ses_1") || !strings.Contains(closed[1], "ses_2") {
		t.Fatalf("closed=%v", closed)
	}
	if !strings.Contains(output.String(), "Closed 2 sessions in demo.") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestSessionsCloseAllClosesEveryOpenSessionAndRetainsHistory(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var closed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open"}, {"id": "ses_2", "name": "api", "state": "open"}, {"id": "ses_3", "name": "old", "state": "closed"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/close"):
			closed = append(closed, r.URL.Path)
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "sessions", "close", "demo", "--all", "--yes"}, &output, &output); code != 0 {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
	if len(closed) != 2 || !strings.Contains(output.String(), "Open sessions to close: 2") || !strings.Contains(output.String(), "Session history was retained") {
		t.Fatalf("closed=%v output=%q", closed, output.String())
	}
}

func TestSessionDeleteAllRequiresConfirmationAndRejectsSessionArgument(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	mutated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open", "is_default": true}, {"id": "ses_2", "name": "work", "state": "open"}}, "pagination": map[string]any{"next_offset": nil}})
		default:
			mutated = true
			t.Fatalf("unexpected request before confirmation: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "session", "delete", "demo", "--all"}, &output, &output); code != 1 || mutated || !strings.Contains(output.String(), "Non-default sessions to delete: 1") || !strings.Contains(output.String(), "requires --yes") {
		t.Fatalf("code=%d mutated=%t output=%q", code, mutated, output.String())
	}

	root := newRootCommand()
	root.SetArgs([]string{"session", "delete", "um_1", "shell-2", "--all", "--yes"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "usage: pb session delete") {
		t.Fatalf("err=%v, want mutually exclusive usage error", err)
	}
}

func TestSessionDeleteAllDeletesOpenAndClosedNonDefaultSessions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_1", "name": "default", "state": "open", "is_default": true}, {"id": "ses_2", "name": "work", "state": "open"}, {"id": "ses_3", "name": "old", "state": "closed"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/projects/prj_1/terminal-sessions/"):
			deleted = append(deleted, r.URL.Path)
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "sessions", "delete", "demo", "--all", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("code=%d output=%q", code, output.String())
	}
	if len(deleted) != 2 || !strings.HasSuffix(deleted[0], "/ses_2") || !strings.HasSuffix(deleted[1], "/ses_3") || !strings.Contains(output.String(), `"deleted":2`) {
		t.Fatalf("deleted=%v output=%q", deleted, output.String())
	}
}

func TestSessionDeleteOpenSessionSendsDelete(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/prj_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "ses_2", "name": "work", "state": "open"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/projects/prj_1/terminal-sessions/ses_2":
			deleted = true
			writeAPIData(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "session", "delete", "demo", "work", "--yes", "--json"}, &output, &output); code != 0 || !deleted || !strings.Contains(output.String(), `"deleted":true`) {
		t.Fatalf("code=%d deleted=%t output=%q", code, deleted, output.String())
	}
}

func TestPreviewsListsAndPurgesOnlySelectedEnvironment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var revoked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "prj_1", "name": "demo", "state": "ready"}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/previews":
			writeAPIData(t, w, []map[string]any{
				{"id": "prv_1", "environment_id": "prj_1", "project_id": "prj_1", "logical_name": "web", "environment_name": "demo", "state": "ready", "url": "https://one.example.test", "target_port": 3000},
				{"id": "prv_2", "environment_id": "prj_2", "project_id": "prj_2", "logical_name": "other", "environment_name": "other", "state": "ready", "url": "https://two.example.test", "target_port": 4000},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/previews/"):
			revoked = append(revoked, r.URL.Path)
			writeAPIData(t, w, map[string]any{"id": "prv_1", "state": "removed"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "previews"}, &output, &output); code != 0 || !strings.Contains(output.String(), "web") || !strings.Contains(output.String(), "other") {
		t.Fatalf("list code=%d output=%q", code, output.String())
	}
	output.Reset()
	if code := run(context.Background(), []string{"--config", configPath, "previews", "revoke", "demo", "--all"}, &output, &output); code != 1 || len(revoked) != 0 || !strings.Contains(output.String(), "Active previews to revoke: 1") || !strings.Contains(output.String(), "requires --yes") {
		t.Fatalf("unconfirmed revoke code=%d revoked=%v output=%q", code, revoked, output.String())
	}
	output.Reset()
	if code := run(context.Background(), []string{"--config", configPath, "previews", "revoke", "demo", "--all", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("revoke code=%d output=%q", code, output.String())
	}
	if len(revoked) != 1 || revoked[0] != "/v1/previews/prv_1" || !strings.Contains(output.String(), `"revoked":1`) {
		t.Fatalf("revoked=%v output=%q", revoked, output.String())
	}
}

func TestSessionListAcceptsDefaultEnvironment(t *testing.T) {
	root := newRootCommand()
	command, remaining, err := root.Find([]string{"session", "list"})
	if err != nil || command == root || len(remaining) != 0 {
		t.Fatalf("session list lookup command=%v remaining=%q err=%v", command, remaining, err)
	}
	if err := command.Args(command, nil); err != nil {
		t.Fatalf("session list rejected omitted environment: %v", err)
	}
}

func TestResolveMachineTargetRejectsAmbiguousNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAPIData(t, w, map[string]any{"items": []map[string]any{
			{"id": "um_1", "display_name": "Studio"}, {"id": "um_2", "display_name": "studio"},
		}, "pagination": map[string]any{"next_offset": nil}})
	}))
	defer srv.Close()
	_, _, err := resolveUserMachineTarget(context.Background(), api.New(srv.URL, config.Credential{AccessToken: "token"}, srv.Client()), "studio")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v, want ambiguity", err)
	}
}

func TestResolveSetupModeRequiresExplicitModeWithoutTTY(t *testing.T) {
	if _, err := resolveSetupMode("", false, io.Discard); err == nil || !strings.Contains(err.Error(), "requires --mode") {
		t.Fatalf("err=%v, want non-interactive mode requirement", err)
	}
	for _, mode := range []string{"receive", "session", "host"} {
		got, err := resolveSetupMode(mode, false, io.Discard)
		if err != nil || got != mode {
			t.Fatalf("resolveSetupMode(%q)=(%q,%v)", mode, got, err)
		}
	}
	if _, err := resolveSetupMode("interactive", false, io.Discard); err == nil || !strings.Contains(err.Error(), "receive, session, or host") {
		t.Fatalf("err=%v, want supported modes", err)
	}
}

func TestMachineHomeActionsFollowConfiguredCapabilities(t *testing.T) {
	machine := api.UserMachine{ID: "machine_actions", SetupMode: "receive", Capabilities: api.MachineCapabilities{
		FileReceive: api.MachineCapability{Configured: true}, PreviewLaunch: api.MachineCapability{Configured: true},
	}}
	actions := machineHomeActions(machine)
	ids := make([]string, len(actions))
	for index, action := range actions {
		ids[index] = action.ID
	}
	if !slices.Equal(ids, []string{"rename", "send", "preview", "previews"}) {
		t.Fatalf("receive actions=%v", ids)
	}
	machine.SetupMode = "host"
	machine.Capabilities.TerminalHost.Configured = true
	actions = machineHomeActions(machine)
	ids = ids[:0]
	for _, action := range actions {
		ids = append(ids, action.ID)
	}
	if !slices.Equal(ids, []string{"rename", "terminal", "codex", "send", "preview", "sessions", "previews", "allow-sleep", "keep-awake"}) {
		t.Fatalf("host actions=%v", ids)
	}
}

func TestMachineStatusSummarySeparatesAvailabilityFromMode(t *testing.T) {
	tests := []struct {
		name    string
		machine api.UserMachine
		want    string
	}{
		{
			name:    "online host",
			machine: api.UserMachine{Online: true, SetupMode: "host", Platform: "linux", Architecture: "arm64"},
			want:    "Online  ·  Host",
		},
		{
			name:    "offline receive",
			machine: api.UserMachine{SetupMode: "receive", Platform: "darwin", Architecture: "arm64"},
			want:    "Offline  ·  Receive only",
		},
		{
			name:    "inactive session",
			machine: api.UserMachine{SetupMode: "session"},
			want:    "Session only",
		},
		{
			name:    "legacy host inferred from capability",
			machine: api.UserMachine{State: "disconnected", Capabilities: api.MachineCapabilities{TerminalHost: api.MachineCapability{Configured: true}}},
			want:    "Offline  ·  Host",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := machineStatusSummary(test.machine); got != test.want {
				t.Fatalf("summary=%q want=%q", got, test.want)
			}
		})
	}
}

func TestAsyncHomeValueStartsImmediatelyAndTracksFreshness(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	value := startAsyncHomeValue(context.Background(), func(context.Context) (string, error) {
		close(started)
		<-release
		return "ready", nil
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background load did not start")
	}
	if value.ready() {
		t.Fatal("blocked load reported ready")
	}
	close(release)
	got, err := value.await(context.Background())
	if err != nil || got != "ready" || !value.fresh() {
		t.Fatalf("value=%q err=%v fresh=%t", got, err, value.fresh())
	}
	value.fetchedAt = time.Now().Add(-homePrefetchFreshness - time.Second)
	if value.fresh() {
		t.Fatal("expired prefetch remained fresh")
	}
}

func TestMachinesSortCurrentDeviceLast(t *testing.T) {
	machines := []api.UserMachine{{ID: "current", DisplayName: "Local"}, {ID: "favorite", DisplayName: "Favorite"}, {ID: "remote", DisplayName: "Remote"}}
	favorites := favoriteSet{}
	favorites.Set("machine", "current", true)
	favorites.Set("machine", "favorite", true)
	sortMachinesForDisplay(machines, favorites, "current")
	if got := []string{machines[0].ID, machines[1].ID, machines[2].ID}; !slices.Equal(got, []string{"favorite", "remote", "current"}) {
		t.Fatalf("machine order=%v", got)
	}
	if got := machineDisplayTitle(machines[2], "current"); got != "Local (this device)" {
		t.Fatalf("current title=%q", got)
	}
}

func TestDroppedFilePathsParsesQuotedAndEscapedPaths(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first file.txt")
	second := filepath.Join(directory, "second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	value := strconv.Quote(first) + " " + strings.ReplaceAll(second, " ", "\\ ")
	paths, err := droppedFilePaths(value)
	if err != nil || !slices.Equal(paths, []string{first, second}) {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	if _, err := droppedFilePaths(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing dropped file was accepted")
	}
}

func TestSetupRollbackContextSurvivesCanceledCommand(t *testing.T) {
	type contextKey string
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), contextKey("operation"), "setup"))
	cancelParent()

	rollback, cancelRollback := setupRollbackContext(parent)
	defer cancelRollback()
	if err := rollback.Err(); err != nil {
		t.Fatalf("rollback context inherited cancellation: %v", err)
	}
	if got := rollback.Value(contextKey("operation")); got != "setup" {
		t.Fatalf("rollback context value=%v", got)
	}
	if deadline, ok := rollback.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 15*time.Second {
		t.Fatalf("rollback deadline=(%v,%t)", deadline, ok)
	}
}

func TestConfigCommandsAreDiscoverableAndUnassignRequiresConfirmation(t *testing.T) {
	root := newRootCommand()
	for _, path := range []string{"config assign", "config unassign", "config show", "config path"} {
		command, _, err := root.Find(strings.Fields(path))
		if err != nil || command.CommandPath() != "pb "+path {
			t.Fatalf("find %q command=%v err=%v", path, command, err)
		}
	}
	root.SetArgs([]string{"config", "unassign", "prj_1"})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "requires --yes") {
		t.Fatalf("err=%v", err)
	}
}

func TestCompatibilityOnlyCommandsAreAbsent(t *testing.T) {
	root := newRootCommand()
	var help bytes.Buffer
	root.SetOut(&help)
	root.SetErr(&help)
	root.SetArgs([]string{"--help"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("help err=%v", err)
	}
	if strings.Contains(strings.ToLower(help.String()), "e2ee") || strings.Contains(strings.ToLower(help.String()), "noise") {
		t.Fatalf("public help exposes private transport internals: %q", help.String())
	}
	root = newRootCommand()
	for _, child := range root.Commands() {
		if child.Name() == "e2ee" {
			t.Fatal("internal transport encryption is still exposed as a public command")
		}
	}
	for parentName, removed := range map[string][]string{
		"config":   {"enable", "disable"},
		"preview":  {"remove", "purge"},
		"previews": {"purge"},
		"session":  {"purge"},
		"sessions": {"purge"},
	} {
		parent, _, err := root.Find([]string{parentName})
		if err != nil {
			t.Fatal(err)
		}
		for _, removedName := range removed {
			for _, child := range parent.Commands() {
				if child.Name() == removedName {
					t.Fatalf("compatibility-only command %q is still registered under %q", removedName, parentName)
				}
			}
		}
	}
}

func TestPrivateTransportLifecycleIsIntegratedIntoPublicWorkflows(t *testing.T) {
	root := newRootCommand()
	for _, path := range []string{"auth login", "setup"} {
		entry, _, err := root.Find(strings.Fields(path))
		if err != nil || entry.CommandPath() != "pb "+path {
			t.Fatalf("find %q command=%v err=%v", path, entry, err)
		}
	}
	login, _, _ := root.Find([]string{"auth", "login"})
	if login.Flags().Lookup("recovery-key") == nil {
		t.Fatal("auth login does not own recovery continuation")
	}
	setup, _, _ := root.Find([]string{"setup"})
	if setup.Flags().Lookup("recovery-output") == nil {
		t.Fatal("setup does not own recovery backup")
	}
}

func TestConfigSetRejectsRemovedTerminalProfile(t *testing.T) {
	root := newRootCommand()
	root.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "config", "set", "terminal-profile", "full"})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "usage: pb config set server <url>") {
		t.Fatalf("err=%v", err)
	}
}

func TestStatusBarConfigCommandsPersistValidatePreviewAndReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, args := range [][]string{
		{"--config", path, "config", "status-bar", "set", "theme", "dark"},
		{"--config", path, "config", "status-bar", "set", "privacy", "true"},
		{"--config", path, "config", "status-bar", "set", "center", "none"},
		{"--config", path, "config", "status-bar", "set", "right", "activity,connection"},
	} {
		if code := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
			t.Fatalf("%v exited %d", args, code)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StatusBar.Theme != "dark" || !cfg.StatusBar.Privacy || strings.Join(cfg.StatusBar.Right, ",") != "activity,connection" {
		t.Fatalf("persisted status bar = %+v", cfg.StatusBar)
	}
	var preview bytes.Buffer
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "preview", "--width", "60"}, &preview, &preview); code != 0 {
		t.Fatalf("preview exited %d: %q", code, preview.String())
	}
	if lines := strings.Count(strings.TrimSpace(preview.String()), "\n") + 1; lines != 3 {
		t.Fatalf("preview lines = %d: %q", lines, preview.String())
	}
	var invalid bytes.Buffer
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "set", "accent", "not-a-color"}, &invalid, &invalid); code != 2 {
		t.Fatalf("invalid color exited %d: %q", code, invalid.String())
	}
	if code := run(context.Background(), []string{"--config", path, "config", "status-bar", "reset"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("reset exited %d", code)
	}
	cfg, err = config.Load(path)
	if err != nil || cfg.StatusBar.Theme != config.DefaultStatusBarTheme || cfg.StatusBar.Privacy {
		t.Fatalf("reset status bar = %+v err=%v", cfg.StatusBar, err)
	}
}

func TestConnectStatusBarOverridesAreValidated(t *testing.T) {
	var output bytes.Buffer
	if code := run(context.Background(), []string{"connect", "demo", "--status-bar-theme", "rainbow"}, &output, &output); code != 2 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
}

func TestConfigAssignHostedMachineJSONContract(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var assigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "mch_1", "environment_id": "prj_1", "display_name": "demo", "machine_kind": "hosted", "setup_roles": []string{"host"}}}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/config-repositories":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "provider": "github", "external_ref": "acme/config", "display_name": "Shared"}}})
		case "GET /v1/machines/mch_1/config-assignment":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "not_found_or_forbidden", "message": "not found"}})
		case "PUT /v1/machines/mch_1/config-assignment":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["mode"] != "push_only" {
				t.Fatalf("assignment body=%v err=%v", body, err)
			}
			assigned = true
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "machine_id": "mch_1", "environment_id": "prj_1", "repository_id": "cfgrepo_1", "mode": "push_only", "consent_state": "not_required", "version": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Shared", "demo", "--mode", "push-only", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !assigned {
		t.Fatal("assignment endpoint was not called")
	}
	var got struct {
		Version    string               `json:"version"`
		Outcome    string               `json:"outcome"`
		Assignment api.ConfigAssignment `json:"assignment"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.Version != "1" || got.Outcome != "confirmed" || got.Assignment.EnvironmentID != "prj_1" || got.Assignment.Mode != "push_only" {
		t.Fatalf("output=%q decoded=%+v err=%v", output.String(), got, err)
	}
}

func TestConfigAssignMachineRequiresPlaintextConsentAndAcceptsExactRevision(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	mutations := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "environment_id": "env_1", "display_name": "Studio"}}, "pagination": map[string]any{"next_offset": nil}})
		case "GET /v1/config-repositories":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "cfgrepo_1", "display_name": "Dotfiles"}}})
		case "GET /v1/machines/um_1/config-assignment":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found_or_forbidden","message":"not found"}}`))
		case "PUT /v1/machines/um_1/config-assignment":
			mutations++
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "environment_id": "env_1", "repository_id": "cfgrepo_1", "mode": "bidirectional", "consent_state": "pending", "warning_revision": "plain-v1", "version": 1})
		case "GET /v1/machines/um_1/config-assignment/warning":
			writeAPIData(t, w, map[string]any{"revision": "plain-v1", "machine_name": "Studio", "repository_name": "Dotfiles", "repository_visibility": "ordinary plaintext", "history_retention": "Git history retains versions", "access_consequence": "repository access may read content"})
		case "POST /v1/machines/um_1/config-assignment/consent":
			mutations++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["warning_revision"] != "plain-v1" || body["expected_version"] != float64(1) {
				t.Fatalf("consent body=%v err=%v", body, err)
			}
			writeAPIData(t, w, map[string]any{"id": "cfgasn_1", "environment_id": "env_1", "repository_id": "cfgrepo_1", "mode": "bidirectional", "consent_state": "accepted", "warning_revision": "plain-v1", "version": 2})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var rejected bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Dotfiles", "Studio", "--mode", "bidirectional"}, &rejected, &rejected); code == 0 || mutations != 0 || !strings.Contains(rejected.String(), "ordinary plaintext") {
		t.Fatalf("exit=%d mutations=%d output=%q", code, mutations, rejected.String())
	}
	var accepted bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "config", "assign", "Dotfiles", "Studio", "--mode", "bidirectional", "--yes", "--json"}, &accepted, &accepted); code != 0 {
		t.Fatalf("exit=%d output=%q", code, accepted.String())
	}
	if mutations != 2 || !strings.Contains(accepted.String(), `"consent_state":"accepted"`) {
		t.Fatalf("mutations=%d output=%q", mutations, accepted.String())
	}
}

func TestMachineRevokeJSONOutputContract(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	var disconnected bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio"}}, "pagination": map[string]any{"next_offset": nil}})
		case "POST /v1/machines/um_1/disconnect":
			disconnected = true
			writeAPIData(t, w, map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "revoke", "Studio", "--yes", "--json"}, &output, &output); code != 0 {
		t.Fatalf("exit code=%d output=%q", code, output.String())
	}
	if !disconnected {
		t.Fatal("disconnect endpoint was not called")
	}
	var got struct {
		Version     string `json:"version"`
		UserMachine struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			State       string `json:"state"`
		} `json:"machine"`
		Outcome string `json:"outcome"`
		Retry   string `json:"retry"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode output %q: %v", output.String(), err)
	}
	if got.Version != "1" || got.UserMachine.ID != "um_1" || got.UserMachine.DisplayName != "Studio" || got.UserMachine.State != "disconnected" || got.Outcome != "confirmed" || got.Retry != "not_required" {
		t.Fatalf("output=%s", output.String())
	}
}

func TestMachineAddPrintsOneShotEnrollmentCommands(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/machine-enrollments" {
			http.NotFound(w, r)
			return
		}
		writeAPIData(t, w, api.MachineEnrollmentStart{ID: "ume_1", BootstrapToken: "one-shot-token", ServerURL: "https://api.paperboat.test"})
	}))
	defer srv.Close()
	writeTestProfile(t, dir, configPath, srv.URL)

	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "machine", "add", "--role", "client", "--name", "Victus"}, &output, &output); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if !strings.Contains(output.String(), "Victus-one-shot-token") || !strings.Contains(output.String(), "get.pprbt.dev/install?p=") || !strings.Contains(output.String(), "PowerShell or Command Prompt") || !strings.Contains(output.String(), `iwr '`) || !strings.Contains(output.String(), `-OutFile "$env:TEMP\pb.ps1"; & "$env:TEMP\pb.ps1"`) || strings.Contains(output.String(), "iex") || strings.Contains(output.String(), "powershell -NoLogo") || strings.Contains(output.String(), "--setup-mode") || strings.Contains(output.String(), "PAPERBOAT_SERVER") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestDefaultEnvironmentUsesStableRememberedIDWithoutListing(t *testing.T) {
	client := api.New("https://api.paperboat.test", config.Credential{AccessToken: "token"}, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("remembered target should not list environments")
		return nil, nil
	})})
	got, err := defaultEnvironment(context.Background(), client, "um_1")
	if err != nil || got != "um_1" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func TestDefaultEnvironmentSelectsOnlyAvailableTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects":
			writeAPIData(t, w, map[string]any{"items": []any{}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 0}})
		case "/v1/machines":
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "um_1", "display_name": "Studio", "online": true, "capabilities": map[string]any{"terminal_host": map[string]any{"configured": true, "observed": true}}}}, "pagination": map[string]any{"limit": 200, "offset": 0, "total": 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := defaultEnvironment(context.Background(), api.New(server.URL, config.Credential{AccessToken: "token"}, server.Client()), "")
	if err != nil || got != "um_1" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func TestRootWithoutArgumentsAttemptsPrimaryWorkflow(t *testing.T) {
	var output bytes.Buffer
	app := newApp()
	app.Writer = &output
	app.ErrWriter = &output
	err := app.Run([]string{"pb", "--config", filepath.Join(t.TempDir(), "config.json")})
	if err == nil {
		t.Fatal("expected an actionable setup error")
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("root stopped at generic help: %q", output.String())
	}
}

func TestCobraRootWithoutArgumentsAttemptsPrimaryWorkflow(t *testing.T) {
	var output bytes.Buffer
	if code := run(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "config.json")}, &output, &output); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("root stopped at generic help: %q", output.String())
	}
}

func TestConnectDoesNotExposeSessionOverrides(t *testing.T) {
	for _, flag := range []string{"--size", "--agent"} {
		t.Run(flag, func(t *testing.T) {
			err := newApp().Run([]string{"pb", flag, "value", "demo"})
			if err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestConnectWithoutServerDoesNotRunLocalShell(t *testing.T) {
	previousDefault := buildinfo.DefaultServerURL
	buildinfo.DefaultServerURL = ""
	t.Cleanup(func() { buildinfo.DefaultServerURL = previousDefault })
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := newApp().Run([]string{"pb", "--config", configPath, "demo"})
	if err == nil || !strings.Contains(err.Error(), "server is not configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestDoctorReturnsFailureWhenBackendIsUnconfigured(t *testing.T) {
	previousDefault := buildinfo.DefaultServerURL
	buildinfo.DefaultServerURL = ""
	t.Cleanup(func() { buildinfo.DefaultServerURL = previousDefault })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"connect":{"ready_timeout_seconds":30,"poll_interval_seconds":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newApp().Run([]string{"pb", "--config", path, "doctor"}); err == nil {
		t.Fatal("doctor returned success for missing server")
	}
}

func TestDoctorProxyDiagnosisIsTypedAndActionable(t *testing.T) {
	for name, test := range map[string]struct {
		failure httptransport.ProxyFailure
		state   string
		want    string
	}{
		"pac":            {httptransport.ProxyAutomaticConfigurationUnsupported, "pac_unsupported", "HTTPS_PROXY"},
		"authentication": {httptransport.ProxyAuthenticationRequired, "authentication_required", "credential-free"},
		"invalid":        {httptransport.ProxyInvalid, "invalid_configuration", "no path"},
	} {
		t.Run(name, func(t *testing.T) {
			diagnosis, ok := doctorProxyDiagnosis(fmt.Errorf("backend: %w", &httptransport.ProxyError{Failure: test.failure}))
			if !ok || diagnosis.State != test.state || !strings.Contains(diagnosis.Recovery, test.want) {
				t.Fatalf("diagnosis=%+v ok=%v", diagnosis, ok)
			}
		})
	}
	if diagnosis, ok := doctorProxyDiagnosis(errors.New("network unavailable")); ok || diagnosis != (proxyDoctorDiagnosis{}) {
		t.Fatalf("diagnosis=%+v ok=%v", diagnosis, ok)
	}
}

func TestCobraAcceptsPersistentFlagsAfterNestedCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var output bytes.Buffer
	if code := run(context.Background(), []string{"config", "path", "--server", "https://api.example.com", "--config", path}, &output, &output); code != 0 {
		t.Fatalf("exit code = %d, output = %q", code, output.String())
	}
}

func TestCobraParsesNestedSessionFlagsWithoutRewriting(t *testing.T) {
	var output bytes.Buffer
	code := run(context.Background(), []string{"sessions", "delete", "demo", "api", "--yes", "--server", "http://127.0.0.1:1"}, &output, &output)
	if code != 1 || strings.Contains(output.String(), "unknown flag") {
		t.Fatalf("exit code = %d output = %q", code, output.String())
	}
}

func TestCobraUsageErrorsReturnExitCodeTwo(t *testing.T) {
	for _, args := range [][]string{
		{"auth", "unknown"},
		{"connect", "demo", "--", "--new"},
		{"demo", "--new", "--session", "api"},
		{"config", "path", "extra"},
	} {
		var output bytes.Buffer
		if code := run(context.Background(), args, &output, &output); code != 2 {
			t.Fatalf("args=%q exit code=%d output=%q", args, code, output.String())
		}
		if !strings.Contains(output.String(), "Usage:") {
			t.Fatalf("args=%q missing usage: %q", args, output.String())
		}
	}
}

func TestBareServerFlagPersistsNormalizedServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if code := run(context.Background(), []string{"--config", path, "--server", "https://api.example.com/"}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://api.example.com" {
		t.Fatalf("server URL = %q", cfg.ServerURL)
	}
}

func TestFileCredentialFallbackPersistsSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := fileCredentialFallback(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.AllowFileFallback {
		t.Fatal("file credential fallback was not enabled")
	}
	if _, ok := store.Secrets.(config.FileSecretStore); !ok {
		t.Fatalf("secret store = %T, want config.FileSecretStore", store.Secrets)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Auth.AllowFileFallback {
		t.Fatal("file credential fallback consent was not persisted")
	}
}

func TestSessionNameReservesOnlyAutomaticShellNames(t *testing.T) {
	if err := validateSessionName("shell-tools"); err != nil {
		t.Fatalf("shell-tools should be valid: %v", err)
	}
	if err := validateSessionName("shell-2"); err == nil {
		t.Fatal("shell-2 should be reserved")
	}
}

func quote(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}

func writeTestProfile(t *testing.T, dir, configPath, serverURL string) {
	t.Helper()
	isolateCommandCredentialLocation(t, dir)
	profileDir := filepath.Join(dir, "credentials")
	configJSON := `{"server_url":` + quote(serverURL) + `,"auth":{"allow_file_fallback":true,"profile_dir":` + quote(profileDir) + `},"connect":{"ready_timeout_seconds":30,"poll_interval_seconds":1,"dial_retries":0}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	store := config.ProfileStore{Path: profileDir, Secrets: config.FileSecretStore{Dir: filepath.Join(profileDir, "secrets")}}
	expires := time.Now().Add(time.Hour)
	err := store.Save(config.Profile{Issuer: serverURL, CLIClientSessionID: "cls_test", AccessExpiresAt: expires}, config.Credential{AccessToken: "token", RefreshToken: "refresh", ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthLogoutIsLocalEvenWhenRemoteRevocationFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke" {
			http.NotFound(w, r)
			return
		}
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"unavailable","message":"try again"}}`))
	}))
	defer server.Close()
	writeTestProfile(t, dir, configPath, server.URL)

	if err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"}); err != nil {
		t.Fatalf("logout err = %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(server.URL); !errors.Is(err, config.ErrNoCredentials) {
		t.Fatalf("active profile err = %v", err)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
	if attempts != 1 {
		t.Fatalf("remote revocation attempts = %d", attempts)
	}
}

func TestAuthLogoutIgnoresFailedHistoricalRevocationAfterCurrentSucceeds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer refresh-old" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"old revocation failed"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	writeTestProfile(t, dir, configPath, server.URL)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(server.URL, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := newApp().Run([]string{"pb", "--config", configPath, "auth", "logout"}); err != nil {
		t.Fatalf("logout err = %v", err)
	}
	if _, err := store.Load(server.URL); !errors.Is(err, config.ErrNoCredentials) {
		t.Fatalf("active profile err = %v", err)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %#v", pending)
	}
}

func TestDrainPendingRevocationsProcessesMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	store := config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	var revoked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revoked = append(revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	if err := store.QueueRevocation(server.URL, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(server.URL, "cls_failed_login", "refresh-new"); err != nil {
		t.Fatal(err)
	}
	if err := drainPendingRevocations(context.Background(), server.URL, store); err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked = %#v", revoked)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
}

func TestCleanupIssuedSessionQueuesAndRevokesSwitchSession(t *testing.T) {
	dir := t.TempDir()
	store := config.ProfileStore{Path: dir, Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	var revoked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revoked = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	if err := cleanupIssuedSession(server.URL, "cls_new", "refresh-new", store); err != nil {
		t.Fatal(err)
	}
	if revoked != "refresh-new" {
		t.Fatalf("revoked token = %q", revoked)
	}
	pending, err := store.PendingRevocations(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending revocations = %d", len(pending))
	}
}

func TestForwardedTerminalEnvFiltersInvalidAndUnset(t *testing.T) {
	t.Setenv("PB_TEST_TERM", "xterm-256color")
	t.Setenv("PB_TEST_EMPTY", "")
	env := forwardedTerminalEnv([]string{"PB_TEST_TERM", "PB_TEST_EMPTY", "PB_TEST_UNSET_VAR", "bad-key!"})
	if len(env) != 1 || env["PB_TEST_TERM"] != "xterm-256color" {
		t.Fatalf("env = %#v", env)
	}
}

func TestTerminalHostErrorDistinguishesCapabilityAndAvailability(t *testing.T) {
	receive := api.UserMachine{Online: true}
	var apiErr *api.APIError
	if err := terminalHostError(receive); !errors.As(err, &apiErr) || apiErr.Code != "machine_capability_unavailable" {
		t.Fatalf("receive error = %#v", err)
	}
	host := receive
	host.Capabilities.TerminalHost.Configured = true
	if err := terminalHostError(host); !errors.As(err, &apiErr) || apiErr.Code != "machine_offline" {
		t.Fatalf("offline host error = %#v", err)
	}
	host.Capabilities.TerminalHost.Observed = true
	if err := terminalHostError(host); err != nil {
		t.Fatalf("ready host error = %v", err)
	}
}

func TestServeCommandContractValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing path", args: []string{"serve"}, want: "requires <path>"},
		{name: "invalid private duration", args: []string{"serve", file, "--duration", "0s"}, want: "positive --duration"},
		{name: "duration conflict", args: []string{"serve", file, "--public", "--duration", "1h", "--indefinite"}, want: "--duration"},
		{name: "spa file", args: []string{"serve", file, "--public", "--spa"}, want: "--spa requires a directory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := newRootCommand()
			root.SetArgs(test.args)
			err := root.ExecuteContext(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestServeCommandIsLocalOnly(t *testing.T) {
	root := newRootCommand()
	serveEntry, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	if serveEntry.Flags().Lookup("machine") != nil {
		t.Fatal("serve exposes a machine selector")
	}
	for _, name := range []string{"name", "duration", "indefinite", "detach", "spa", "public", "listen-port", "json"} {
		if serveEntry.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s", name)
		}
	}
}

func TestServeDefaultsToPrivateWithoutSetup(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", filepath.Join(t.TempDir(), "unconfigured"))
	var stdout, stderr bytes.Buffer
	root := newRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "serve", file, "--json", "--duration", "1s"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		OK   bool `json:"ok"`
		Data struct {
			URL        string `json:"url"`
			Visibility string `json:"visibility"`
			Listener   string `json:"listener"`
		} `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout = %q: %v", stdout.String(), err)
	}
	if !envelope.OK || envelope.Data.Visibility != "private" || envelope.Data.Listener != "loopback" || !strings.HasPrefix(envelope.Data.URL, "http://127.0.0.1:") {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestListLocalPrivateServesReadsOwnerOnlyDescriptor(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", root)
	source := filepath.Join(root, "site")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	descriptor := map[string]any{
		"schema": "paperboat.preview-runtime/v1", "name": "docs", "bind_address": "127.0.0.1", "port": 32000,
		"service_generation": 1, "indefinite": false, "expires_at": expires, "service_definition": filepath.Join(root, "docs.service"),
		"record": map[string]any{"id": "", "environment_id": "", "logical_name": "", "preview_key": "", "url": "http://127.0.0.1:32000", "target_port": 0, "state": "ready", "expires_at": expires},
		"serve":  map[string]any{"source_path": source, "source_kind": "directory", "source_identity": "dev:1:ino:2", "spa": false, "owner_mode": "detached", "visibility": "private", "listen_port": 0},
	}
	data, _ := json.Marshal(descriptor)
	directory := filepath.Join(root, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(filepath.Join(directory, "docs.json"), data, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		t.Fatal(err)
	}
	items := listLocalPrivateServes()
	if len(items) != 1 || items[0].Name != "docs" || items[0].URL != "http://127.0.0.1:32000" || items[0].SourcePath != source {
		t.Fatalf("items = %#v", items)
	}
}

func TestServeJSONInvocationFailureUsesEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"serve", "--json"}, &stdout, &stderr)
	if code != 2 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var envelope struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Error         struct {
			Code               string `json:"code"`
			Category           string `json:"category"`
			PublicStateCreated any    `json:"public_state_created"`
			Cleanup            string `json:"cleanup"`
		} `json:"error"`
	}
	if json.Unmarshal(stdout.Bytes(), &envelope) != nil || envelope.SchemaVersion != "1.0" || envelope.OK || envelope.Error.Code != "serve_invocation_invalid" || envelope.Error.Category != "usage" || envelope.Error.PublicStateCreated != "unknown" || envelope.Error.Cleanup != "not_required" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestServeProtocolIncompatibleUsesTypedEnvelope(t *testing.T) {
	envelope := serveErrorEnvelope(errServeProtocolIncompatible)
	if envelope["code"] != "protocol_incompatible" || envelope["category"] != "protocol" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestNormalizeServeName(t *testing.T) {
	if got := normalizeServeName("", "My Report (Final).HTML"); got != "my-report-final-html" {
		t.Fatalf("derived name = %q", got)
	}
	if got := normalizeServeName("docs_v2", "ignored"); got != "docs_v2" {
		t.Fatalf("explicit name = %q", got)
	}
}

func TestEnrichLocalServeSources(t *testing.T) {
	stateRoot := t.TempDir()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
	directory := filepath.Join(stateRoot, "previews", "active")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "site")
	descriptor := func(id, path string) []byte {
		return []byte(fmt.Sprintf(`{"schema":"paperboat.preview-runtime/v1","record":{"id":%q},"serve":{"source_path":%q}}`, id, path))
	}
	if err := atomicfile.Write(filepath.Join(directory, "valid.json"), descriptor("served", source), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "permissive.json"), descriptor("unsafe", "/private/unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := atomicfile.Write(target, descriptor("linked", "/private/linked"), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "linked.json")); err != nil {
		t.Fatal(err)
	}
	items := enrichLocalServeSources([]api.Preview{
		{ID: "served", SourceKind: "directory"},
		{ID: "unsafe", SourceKind: "file"},
		{ID: "linked", SourceKind: "file"},
		{ID: "served", SourceKind: "application"},
	})
	if items[0].SourcePath != filepath.Clean(source) {
		t.Fatalf("valid source path = %q", items[0].SourcePath)
	}
	for index := 1; index < len(items); index++ {
		if items[index].SourcePath != "" {
			t.Fatalf("unsafe item %d was enriched with %q", index, items[index].SourcePath)
		}
	}
}

func TestSelectStatusMachinePrefersIDAndRejectsAmbiguousAlias(t *testing.T) {
	machines := []localapi.MachineStatus{{ID: "machine_1", Alias: "Studio"}, {ID: "Studio", Alias: "Other"}, {ID: "machine_2", Alias: "studio"}}
	selected, err := selectStatusMachine(machines, "Studio")
	if err != nil || selected.ID != "Studio" {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	if _, err := selectStatusMachine(machines, "STUDIO"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous err=%v", err)
	}
	if _, err := selectStatusMachine(machines, "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing err=%v", err)
	}
}

func TestWriteStatusIncludesOperationalFieldsAndSafeHealth(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{
		Schema: localapi.SnapshotSchemaV1, Generation: 3, ObservedAt: now, DaemonState: "degraded",
		Health:   []localapi.HealthItem{{Code: "control_plane_unavailable", Severity: "error", Title: "Control plane is unavailable", Recovery: "Check network access", ETag: "control_plane_unavailable"}},
		Machines: []localapi.MachineStatus{{ID: "machine_1", Alias: "Studio Mac", Eligible: true, RuntimeState: "ready", Generation: 4, LastObservedAt: &now, ActiveConsumers: 2, SelectedPath: "relay", RelayRegion: "bom", TransferReadiness: "ready", PreviewReadiness: "degraded", SSHReadiness: "unavailable"}},
	}
	var output bytes.Buffer
	writeStatus(&output, snapshot)
	for _, expected := range []string{"Daemon: degraded", "Control plane is unavailable", "Studio Mac (machine_1)", "Runtime: ready", "Path: relay/bom", "Consumers: 2", "Transfer: ready", "Preview: degraded", "SSH: unavailable"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestDoctorCommandUsesOwnerSocketAndStableJSON(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home, runtimeRoot := filepath.Join(root, "home"), filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", filepath.Join(root, "unconfigured-runtime"))
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/me" || request.Header.Get("Authorization") != "Bearer token" {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		writeAPIData(t, writer, api.Me{ID: "user_1", Email: "owner@example.test"})
	}))
	defer backend.Close()
	configPath := filepath.Join(root, "config.json")
	writeTestProfile(t, root, configPath, backend.URL)
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 15, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready", Machines: []localapi.MachineStatus{}}
	store, err := localapi.NewSnapshotStore(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForCommandSocket(t, paths.SocketPath)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "doctor", "--json"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var report doctorpkg.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report.Schema != doctorpkg.SchemaV1 || report.Overall != "degraded" || stderr.Len() != 0 {
		t.Fatalf("report=%#v decode=%v stderr=%q", report, err, stderr.String())
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	checks := make(map[string]doctorpkg.Check, len(report.Checks))
	for _, check := range report.Checks {
		checks[check.Code] = check
	}
	if checks["authentication"].Status != doctorpkg.StatusPass || checks["daemon"].Status != doctorpkg.StatusPass || checks["local_state"].Status != doctorpkg.StatusWarning || checks["udp_ipv4"].Status != doctorpkg.StatusPass {
		t.Fatalf("checks=%#v", checks)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestWaitCommandUsesLocalWatchAndStableExitResults(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home := filepath.Join(root, "home")
	runtimeRoot := filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("PAPERBOAT_CONFIG", filepath.Join(root, "config", "paperboat.json"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 13, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{
		Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready",
		Machines: []localapi.MachineStatus{{ID: "machine_1", Alias: "Studio Mac", Eligible: true, RuntimeState: "ready", Generation: 4, SelectedPath: "none", TransferReadiness: "ready", PreviewReadiness: "ready", SSHReadiness: "unavailable", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown"}},
	}
	store, err := localapi.NewSnapshotStore(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForCommandSocket(t, paths.SocketPath)

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", filepath.Join(root, "config", "paperboat.json"), "wait", "Studio Mac", "--for", "runtime", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ready code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var ready localwait.Result
	if err := json.Unmarshal(stdout.Bytes(), &ready); err != nil || ready.Schema != localwait.ResultSchemaV1 || ready.Outcome != "ready" || ready.Machine.ID != "machine_1" {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

type commandDiagnosticService struct {
	bundle  diagnostics.Bundle
	markers []string
}

func (s *commandDiagnosticService) Diagnostics(context.Context) (localapi.DiagnosticSnapshot, error) {
	return localapi.DiagnosticSnapshot{Schema: localapi.DiagnosticSnapshotSchemaV1, ObservedAt: time.Now().UTC()}, nil
}
func (s *commandDiagnosticService) RecordBugreportMarker(_ context.Context, phase string) error {
	s.markers = append(s.markers, phase)
	return nil
}
func (s *commandDiagnosticService) CreateBugreport(context.Context) (diagnostics.Bundle, error) {
	return s.bundle, nil
}

func TestBugreportCommandUsesDaemonBundleAndStableJSON(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home, runtimeRoot := filepath.Join(root, "home"), filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 15, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready"}
	store, _ := localapi.NewSnapshotStore(&snapshot)
	bundlePath := filepath.Join(root, "bugreport-pb-0123456789abcdef0123456789abcdef.zip")
	content := []byte("PK command bundle")
	if err := atomicfile.Write(bundlePath, content, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		t.Fatal(err)
	}
	diagnosticService := &commandDiagnosticService{bundle: diagnostics.Bundle{Schema: diagnostics.BundleSchemaV1, Correlation: "pb-0123456789abcdef0123456789abcdef", CreatedAt: now, Path: bundlePath, Bytes: int64(len(content)), Categories: []string{"manifest", "recent_events", "redacted_events", "status"}}}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig.Diagnostics = diagnosticService
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForCommandSocket(t, paths.SocketPath)
	var stdout, stderr bytes.Buffer
	command := newRootCommand()
	command.SetIn(bytes.NewBufferString("\n"))
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"bugreport", "--record", "--json"})
	if err := command.ExecuteContext(ctx); err != nil {
		t.Fatalf("execute error=%T %v stdout=%q stderr=%q", err, err, stdout.String(), stderr.String())
	}
	var result bugreportpkg.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Validate() != nil || !result.BundleCreated || !result.Recorded || result.Uploaded || !slices.Equal(diagnosticService.markers, []string{"start", "end"}) {
		t.Fatalf("result=%#v error=%v markers=%v stdout=%s stderr=%s", result, err, diagnosticService.markers, stdout.String(), stderr.String())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

type bugreportRefreshAuth struct{ calls int }

func (a *bugreportRefreshAuth) Credential() (config.Credential, error) {
	return config.Credential{AccessToken: "stale"}, nil
}

func (a *bugreportRefreshAuth) Refresh() (config.Credential, error) {
	a.calls++
	return config.Credential{AccessToken: "fresh"}, nil
}

func TestRefreshingBugreportServerRetriesAuthorizationWithSameKey(t *testing.T) {
	var keys []string
	expires := time.Now().UTC().Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") == "Bearer stale" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
			return
		}
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": api.DiagnosticUploadIntent{Schema: api.DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "pending", ExpiresAt: expires, UploadMethod: http.MethodPut, UploadURL: "https://uploads.example.test/bundle", UploadHeaders: map[string]string{"Content-Type": "application/zip"}}})
	}))
	defer server.Close()
	auth := &bugreportRefreshAuth{}
	client, err := newRefreshingBugreportServer(server.URL, auth)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateDiagnosticUploadIntent(context.Background(), "same-operation-key", api.DiagnosticUploadIntentRequest{Schema: api.DiagnosticUploadIntentRequestSchemaV1})
	if err != nil || auth.calls != 1 || !slices.Equal(keys, []string{"same-operation-key", "same-operation-key"}) {
		t.Fatalf("err=%v refreshes=%d keys=%v", err, auth.calls, keys)
	}
}

func TestLocalDaemonSnapshotInstallsOnlyForUnavailableSocket(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home := filepath.Join(root, "home")
	runtimeRoot := filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"server_url":"https://api.paperboat.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigPath, configPath)
	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready", Machines: []localapi.MachineStatus{}}
	store, _ := localapi.NewSnapshotStore(&snapshot)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	installCalls := 0
	installer := func(_ context.Context, executable, configPath, server string) error {
		installCalls++
		if !filepath.IsAbs(executable) || configPath != filepath.Join(root, "config.json") || server != "https://api.paperboat.test" {
			t.Fatalf("executable=%q config=%q server=%q", executable, configPath, server)
		}
		serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
		if err != nil {
			return err
		}
		localServer, err := localapi.NewServer(serverConfig)
		if err != nil {
			return err
		}
		go func() { done <- localServer.Run(ctx) }()
		return nil
	}
	rootCommand := newRootCommand()
	rootCommand.SetContext(ctx)
	if err := rootCommand.PersistentFlags().Set("config", filepath.Join(root, "custom-config.json")); err != nil {
		t.Fatal(err)
	}
	if err := rootCommand.PersistentFlags().Set("server", "https://api.paperboat.test"); err != nil {
		t.Fatal(err)
	}
	status, _, err := rootCommand.Find([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	client, got, err := localDaemonSnapshot(status, installer)
	if err != nil || client == nil || got.Generation != 1 || installCalls != 1 {
		t.Fatalf("client=%v snapshot=%#v calls=%d err=%v", client != nil, got, installCalls, err)
	}
	if _, _, err := localDaemonSnapshot(status, installer); err != nil || installCalls != 1 {
		t.Fatalf("existing daemon calls=%d err=%v", installCalls, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestResolveSSHCommandTargetFastUsesWarmSnapshotAndCache(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home := filepath.Join(root, "home")
	runtimeRoot := filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "xdg-state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", filepath.Join(root, "identity"))

	var machineListCalls, sshTargetCalls int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/machines":
			atomic.AddInt32(&machineListCalls, 1)
			writeAPIData(t, w, map[string]any{"items": []map[string]any{}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/machines/mch_1/ssh-target":
			atomic.AddInt32(&sshTargetCalls, 1)
			if r.URL.Query().Get("machine_generation") != "4" {
				t.Errorf("machine_generation = %q", r.URL.Query().Get("machine_generation"))
			}
			writeAPIData(t, w, map[string]any{"type": "machine_target", "version": 1, "machine_id": "mch_1", "machine_generation": 4, "os_user": "root", "port": 22, "reconciliation_version": 1})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	configPath := filepath.Join(root, "config.json")
	writeTestProfile(t, root, configPath, backend.URL)

	identityRoot := filepath.Join(root, "identity")
	identityStore, err := identity.Open(identity.Config{StateRoot: identityRoot})
	if err != nil {
		t.Fatal(err)
	}
	if err := identityStore.SaveRegistration(identity.Registration{
		ServerURL:              backend.URL,
		MachineID:              "mch_source",
		EnvironmentID:          "env_source",
		PublicKeyID:            identityStore.Current().ID,
		PublicIdentityKey:      "test-public-key",
		InboxPath:              filepath.Join(home, "inbox"),
		InstallationGeneration: 1,
		UpdatedAt:              time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{
		Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready",
		Machines: []localapi.MachineStatus{{ID: "mch_1", EnvironmentID: "env_1", WorkspaceRoot: "/root", Alias: "hn-byod-ready", Eligible: true, RuntimeState: "ready", Generation: 4, SelectedPath: "none", TransferReadiness: "unavailable", PreviewReadiness: "unavailable", SSHReadiness: "ready", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown"}},
	}
	store, err := localapi.NewSnapshotStore(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForCommandSocket(t, paths.SocketPath)

	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("config", configPath, "")
	set.String("server", "", "")
	set.String("transport", "", "")
	commandContext := command.NewContext(set)

	client, machine, target, err := resolveSSHCommandTargetFast(commandContext, "hn-byod-ready")
	if err != nil {
		t.Fatalf("fast resolve: %v", err)
	}
	if client == nil || machine.ID != "mch_1" || machine.Alias != "hn-byod-ready" || target.Port != 22 || target.OSUser != "root" {
		t.Fatalf("client=%v machine=%+v target=%+v", client != nil, machine, target)
	}
	if got := atomic.LoadInt32(&machineListCalls); got != 0 {
		t.Fatalf("warm fast path listed machines %d times", got)
	}
	if got := atomic.LoadInt32(&sshTargetCalls); got != 1 {
		t.Fatalf("warm fast path fetched SSH target %d times, want 1", got)
	}

	if _, _, cached, err := resolveSSHCommandTargetFast(commandContext, "hn-byod-ready"); err != nil || cached.Port != 22 || cached.OSUser != "root" {
		t.Fatalf("cached resolve: %+v %v", cached, err)
	}
	if got := atomic.LoadInt32(&machineListCalls); got != 0 {
		t.Fatalf("cached fast path listed machines %d times", got)
	}
	if got := atomic.LoadInt32(&sshTargetCalls); got != 1 {
		t.Fatalf("cached fast path fetched SSH target %d times, want 1", got)
	}

	if _, _, live, err := resolveSSHCommandTargetLive(commandContext, "hn-byod-ready"); err != nil || live.Port != 22 {
		t.Fatalf("live resolve: %+v %v", live, err)
	}
	if got := atomic.LoadInt32(&machineListCalls); got != 0 {
		t.Fatalf("live path listed machines %d times", got)
	}
	if got := atomic.LoadInt32(&sshTargetCalls); got != 2 {
		t.Fatalf("live path fetched SSH target %d times, want 2", got)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestSelectTerminalSessionPrefersWarmMachineSnapshot(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	runtimeRoot := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)

	var catalogCalls int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/projects" || r.URL.Path == "/v1/machines":
			atomic.AddInt32(&catalogCalls, 1)
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/machines/mch_1/terminal-sessions":
			writeAPIData(t, w, map[string]any{"id": "umts_1", "name": "quiet-harbor", "state": "open", "created_at": time.Now(), "updated_at": time.Now()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	paths, err := localdaemon.CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	snapshot := localapi.Snapshot{
		Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready",
		Machines: []localapi.MachineStatus{{ID: "mch_1", EnvironmentID: "env_1", WorkspaceRoot: "/root", Alias: "hn-byod-ready", Eligible: true, RuntimeState: "ready", Generation: 4, SelectedPath: "none", TransferReadiness: "unavailable", PreviewReadiness: "unavailable", SSHReadiness: "unavailable", NATMappingIPv4: "unknown", NATMappingIPv6: "unknown", CaptivePortal: "unknown", PMTU: "unknown", RouterProtocol: "unknown", RouterMapping: "unknown", MappingLifetime: "unknown", UpdateHealth: "unknown"}},
	}
	store, err := localapi.NewSnapshotStore(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := commandLocalAPIServerConfig(paths.SocketPath, store)
	if err != nil {
		t.Fatal(err)
	}
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	waitForCommandSocket(t, paths.SocketPath)

	session, target, machine, err := selectTerminalSession(context.Background(), api.New(backend.URL, config.Credential{AccessToken: "token"}, backend.Client()), "hn-byod-ready", "", "")
	if err != nil {
		t.Fatalf("selectTerminalSession: %v", err)
	}
	if session.ID != "umts_1" || target.kind != environmentUserMachine || target.id != "mch_1" || machine.ID != "mch_1" {
		t.Fatalf("session=%+v target=%+v machine=%+v", session, target, machine)
	}
	if got := atomic.LoadInt32(&catalogCalls); got != 0 {
		t.Fatalf("warm machine resolution consulted the catalog %d times", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestResolveSSHCommandTargetFastFallsBackWithoutWarmSnapshot(t *testing.T) {
	root := commandRuntimeTestRoot(t)
	home := filepath.Join(root, "home")
	runtimeRoot := filepath.Join(root, "runtime")
	for _, directory := range []string{home, runtimeRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "xdg-state"))
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	t.Setenv("TMPDIR", runtimeRoot)
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", filepath.Join(root, "identity"))

	var machineListCalls, sshTargetCalls int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/machines":
			atomic.AddInt32(&machineListCalls, 1)
			writeAPIData(t, w, map[string]any{"items": []map[string]any{{"id": "mch_1", "display_name": "hn-byod-ready", "alias": "hn-byod-ready", "state": "online", "online": true, "installation_generation": 4, "environment_id": "env_1", "workspace_root": "/root", "capabilities": map[string]any{"terminal_host": map[string]any{"configured": true, "observed": true}}}}, "pagination": map[string]any{"next_offset": nil}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/machines/mch_1/ssh-target":
			atomic.AddInt32(&sshTargetCalls, 1)
			writeAPIData(t, w, map[string]any{"type": "machine_target", "version": 1, "machine_id": "mch_1", "machine_generation": 4, "os_user": "root", "port": 2222, "reconciliation_version": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	configPath := filepath.Join(root, "config.json")
	writeTestProfile(t, root, configPath, backend.URL)
	identityRoot := filepath.Join(root, "identity")
	identityStore, err := identity.Open(identity.Config{StateRoot: identityRoot})
	if err != nil {
		t.Fatal(err)
	}
	if err := identityStore.SaveRegistration(identity.Registration{
		ServerURL:              backend.URL,
		MachineID:              "mch_source",
		EnvironmentID:          "env_source",
		PublicKeyID:            identityStore.Current().ID,
		PublicIdentityKey:      "test-public-key",
		InboxPath:              filepath.Join(home, "inbox"),
		InstallationGeneration: 1,
		UpdatedAt:              time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("config", configPath, "")
	set.String("server", "", "")
	set.String("transport", "", "")
	commandContext := command.NewContext(set)

	// No daemon socket exists: the fast path must fall back to the canonical
	// live resolution instead of failing.
	client, machine, target, err := resolveSSHCommandTargetFast(commandContext, "hn-byod-ready")
	if err != nil {
		t.Fatalf("fallback resolve: %v", err)
	}
	if client == nil || machine.ID != "mch_1" || target.Port != 2222 || target.OSUser != "root" {
		t.Fatalf("client=%v machine=%+v target=%+v", client != nil, machine, target)
	}
	if got := atomic.LoadInt32(&machineListCalls); got == 0 {
		t.Fatal("fallback path did not list machines")
	}
	if got := atomic.LoadInt32(&sshTargetCalls); got != 1 {
		t.Fatalf("fallback path fetched SSH target %d times, want 1", got)
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

func TestCollectTunnelHostDiagnosticsUsesLoopbackNoProxyAndStrictBounds(t *testing.T) {
	tracker, err := health.NewHealthTracker(func() time.Time { return time.Unix(100, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(health.HealthUpdate{
		Dimension: health.DimensionService, Status: health.StatusReady, Code: "ready",
		Summary: "Runtime is ready.", RepairAction: "No action is required.",
		CorrelationID: "corr_test", Retry: health.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}
	metrics, err := observability.NewRegistry(observability.DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Record("paperboat_runtime_connector_retries_total", 1, map[string]string{"transport": "quic", "result": "connected"}); err != nil {
		t.Fatal(err)
	}
	events, err := observability.NewEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	if _, err := events.Record(observability.EventInput{
		At: time.Unix(100, 0).UTC(), Severity: observability.SeverityInfo,
		Component: observability.DimensionConfig, Name: "config_applied", Code: "ready",
		Outcome: observability.OutcomeStateChange, Message: "Configuration applied.",
		CorrelationID: "corr_test", Generations: observability.Generations{Config: 7}, Retry: observability.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}

	responseBody, err := json.Marshal(tunnelHostDiagnostics{
		Schema: tunnelHostDiagnosticsSchemaV1, Health: tracker.Snapshot(), Metrics: metrics.Snapshot(), Events: events.Snapshot(), DroppedEvents: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyCalls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		http.Error(w, "proxy must not receive loopback diagnostics", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != tunnelHostDiagnosticsPath {
			t.Fatalf("path=%q", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(responseBody)
	}))
	t.Cleanup(server.Close)
	stateRoot := t.TempDir()
	runtimeDirectory := filepath.Join(stateRoot, "runtime")
	if err := os.Mkdir(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := []byte(fmt.Sprintf(`{"schema":"paperboat.worker-local/v1","listen_address":%q}`, strings.TrimPrefix(server.URL, "http://")))
	if err := os.WriteFile(filepath.Join(runtimeDirectory, "worker-local.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	got, err := collectTunnelHostDiagnostics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != tunnelHostDiagnosticsSchemaV1 || got.Health.ETag != tracker.Snapshot().ETag || len(got.Metrics) == 0 || len(got.Events) != 1 || got.DroppedEvents != 2 {
		t.Fatalf("diagnostics=%#v", got)
	}
	if proxyCalls != 0 {
		t.Fatalf("proxy calls=%d", proxyCalls)
	}
}

func TestCollectTunnelHostDiagnosticsRejectsUnsafeResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "unknown field", body: `{"schema":"paperboat.host-diagnostics/v1","health":{},"metrics":[],"events":[],"dropped_events":0,"token":"secret"}`, want: errTunnelHostDiagnosticsUnavailable},
		{name: "duplicate field", body: `{"schema":"paperboat.host-diagnostics/v1","schema":"paperboat.host-diagnostics/v1","health":{},"metrics":[],"events":[],"dropped_events":0}`, want: errTunnelHostDiagnosticsUnavailable},
		{name: "trailing data", body: `{"schema":"paperboat.host-diagnostics/v1","health":{},"metrics":[],"events":[],"dropped_events":0}{}`, want: errTunnelHostDiagnosticsUnavailable},
		{name: "wrong schema", body: `{"schema":"other/v1","health":{},"metrics":[],"events":[],"dropped_events":0}`, want: errTunnelHostDiagnosticsUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			stateRoot := t.TempDir()
			runtimeDirectory := filepath.Join(stateRoot, "runtime")
			if err := os.Mkdir(runtimeDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			descriptor := []byte(fmt.Sprintf(`{"schema":"paperboat.worker-local/v1","listen_address":%q}`, strings.TrimPrefix(server.URL, "http://")))
			if err := os.WriteFile(filepath.Join(runtimeDirectory, "worker-local.json"), descriptor, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", stateRoot)
			_, err := collectTunnelHostDiagnostics(t.Context())
			if err != test.want {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestTunnelDoctorBundleIncludesTypedHostDiagnosticsAndEvidence(t *testing.T) {
	oldLocal, oldHost, oldDNS := tunnelDoctorLocalReportForCommand, tunnelDoctorHostDiagnosticsForCommand, tunnelDoctorDNSCheckForCommand
	t.Cleanup(func() {
		tunnelDoctorLocalReportForCommand = oldLocal
		tunnelDoctorHostDiagnosticsForCommand = oldHost
		tunnelDoctorDNSCheckForCommand = oldDNS
	})
	tunnelDoctorLocalReportForCommand = func(context.Context) (localDoctorReport, error) {
		return localDoctorReport{HostRuntime: "ready", IdentityState: "available", CredentialState: "available"}, nil
	}
	tunnelDoctorDNSCheckForCommand = func(context.Context) bool { return true }
	tracker, err := health.NewHealthTracker(func() time.Time { return time.Unix(100, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Update(health.HealthUpdate{
		Dimension: health.DimensionService, Status: health.StatusReady, Code: "ready",
		Summary: "Runtime is ready.", RepairAction: "No action is required.", CorrelationID: "corr_test", Retry: health.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}
	metrics, err := observability.NewRegistry(observability.DefaultDescriptors())
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.Record("paperboat_runtime_connector_retries_total", 1, map[string]string{"transport": "tcp_mux", "result": "connected"}); err != nil {
		t.Fatal(err)
	}
	events, err := observability.NewEventLog(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	if _, err := events.Record(observability.EventInput{
		At: time.Unix(100, 0).UTC(), Severity: observability.SeverityInfo, Component: observability.DimensionConfig,
		Name: "config_applied", Code: "ready", Outcome: observability.OutcomeStateChange, Message: "Configuration applied.",
		CorrelationID: "corr_test", Generations: observability.Generations{Config: 7}, Retry: observability.RetryNone,
	}); err != nil {
		t.Fatal(err)
	}
	tunnelDoctorHostDiagnosticsForCommand = func(context.Context) (tunnelHostDiagnostics, error) {
		return tunnelHostDiagnostics{Schema: tunnelHostDiagnosticsSchemaV1, Health: tracker.Snapshot(), Metrics: metrics.Snapshot(), Events: events.Snapshot()}, nil
	}
	dimension := api.TunnelHealthDimension{Status: "healthy", Code: "ready"}
	tunnelHealth := api.TunnelHealth{Schema: api.TunnelV1Schema, Kind: "health", ResourceKind: "tunnel", ResourceID: "tun_1", OverallCode: "ready", Summary: "Tunnel is ready.", RepairAction: "none", Since: time.Unix(1, 0).UTC(), Dimensions: api.TunnelHealthDimensions{Service: dimension, Edge: dimension, Config: dimension, Route: dimension, Origin: dimension, DNS: dimension, Certificate: dimension, Access: dimension, Update: dimension}}
	_, preview, err := buildTunnelDoctorBundle(t.Context(), tunnelHealth, tunnelDoctorBundleDefaultBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Manifest.Items) != 3 {
		t.Fatalf("items=%#v", preview.Manifest.Items)
	}
	if !bytes.Contains(preview.Bytes(), []byte(`"path":"diagnostics/host-runtime.json"`)) {
		t.Fatalf("host diagnostics item missing: %s", preview.Bytes())
	}
	if bytes.Contains(preview.Bytes(), []byte(`"code":"configuration_generation","status":"unavailable"`)) || bytes.Contains(preview.Bytes(), []byte(`"code":"transport_fallback","status":"unavailable"`)) {
		t.Fatalf("typed evidence remained unavailable: %s", preview.Bytes())
	}
}

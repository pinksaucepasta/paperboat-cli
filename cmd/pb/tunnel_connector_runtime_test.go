package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelenrollment"
	"github.com/spf13/cobra"
)

type fakeConnectorEnrollmentClient struct {
	projection  tunnelenrollment.Projection
	err         error
	tunnel, key string
}

func (f *fakeConnectorEnrollmentClient) Enroll(_ context.Context, tunnel, key string) (tunnelenrollment.Projection, error) {
	f.tunnel, f.key = tunnel, key
	return f.projection, f.err
}

func TestRunProductionTunnelConnectorAddUsesStableHostdAndPrintsSafeProjection(t *testing.T) {
	oldClient, oldProbe, oldRepair := connectorEnrollmentLocalClient, tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	defer func() {
		connectorEnrollmentLocalClient, tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldClient, oldProbe, oldRepair
	}()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", t.TempDir())
	tunnelHostRuntimeProbe = func(context.Context, string) error { return nil }
	fake := &fakeConnectorEnrollmentClient{}
	now := time.Now().UTC()
	fake.projection = tunnelenrollment.Projection{Schema: tunnelenrollment.Schema, Kind: "tunnel_connector", TunnelID: "tunnel_01", HostID: "host_01", ConnectorID: "connector_01", OperationID: "operation_01", State: "ready", CredentialReference: "protected-file://paperboat/connectors/key_01", CredentialGeneration: 1, ReadyAt: &now}
	connectorEnrollmentLocalClient = func(string) (tunnelConnectorEnrollmentClient, error) { return fake, nil }
	command := &cobra.Command{}
	var output strings.Builder
	command.SetOut(&output)
	command.SetContext(context.Background())
	if err := runProductionTunnelConnectorAdd(command, "tunnel_01"); err != nil {
		t.Fatal(err)
	}
	if fake.tunnel != "tunnel_01" || !strings.HasPrefix(fake.key, "connector-add-") || !strings.Contains(output.String(), "connector_01") || strings.Contains(strings.ToLower(output.String()), "credential") {
		t.Fatalf("tunnel=%q key=%q output=%q", fake.tunnel, fake.key, output.String())
	}
}

func TestProductionConnectorEnrollmentLocalClientRejectsNonLoopbackAndUsesControlToken(t *testing.T) {
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "local-control-token"), []byte("local-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "worker-local.json"), []byte(`{"schema":"paperboat.worker-local/v1","listen_address":"192.0.2.1:1234"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := productionConnectorEnrollmentLocalClient(root); err == nil {
		t.Fatal("non-loopback accepted")
	}
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tunnelenrollment.Projection{Schema: tunnelenrollment.Schema, Kind: "tunnel_connector", TunnelID: "tunnel_01", HostID: "host_01", ConnectorID: "connector_01", OperationID: "operation_01", State: "ready", CredentialReference: "protected-file://paperboat/connectors/key_01", CredentialGeneration: 1, ReadyAt: &now})
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	descriptor, _ := json.Marshal(map[string]string{"schema": "paperboat.worker-local/v1", "listen_address": address})
	if err := os.WriteFile(filepath.Join(runtimeRoot, "worker-local.json"), descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := productionConnectorEnrollmentLocalClient(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Enroll(context.Background(), "tunnel_01", "local-request-01"); err != nil {
		t.Fatal(err)
	}
}

func TestRunProductionTunnelConnectorAddFailsClosedWhenHostdUnavailable(t *testing.T) {
	oldClient, oldProbe, oldRepair := connectorEnrollmentLocalClient, tunnelHostRuntimeProbe, tunnelHostRuntimeRepair
	defer func() {
		connectorEnrollmentLocalClient, tunnelHostRuntimeProbe, tunnelHostRuntimeRepair = oldClient, oldProbe, oldRepair
	}()
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", t.TempDir())
	tunnelHostRuntimeProbe = func(context.Context, string) error { return errors.New("down") }
	tunnelHostRuntimeRepair = func(context.Context) error { return errors.New("repair failed") }
	command := &cobra.Command{}
	command.SetContext(context.Background())
	if err := runProductionTunnelConnectorAdd(command, "tunnel_01"); err == nil {
		t.Fatal("unavailable hostd reported success")
	}
}

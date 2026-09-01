package tunnelenrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

func TestIssueSendsCanonicalOriginCapabilities(t *testing.T) {
	requestBodies := make(chan []byte, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tunnel_01/connectors/enrollments" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		requestBodies <- requestBody
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": serverEnrollment{
			Schema: api.TunnelV1Schema, Kind: "connector_enrollment", ID: "enrollment_01", TunnelID: "tunnel_01", HostID: "host_01",
			Token: "pbce_" + strings.Repeat("t", 48), ExpiresAt: time.Now().UTC().Add(time.Minute), Capabilities: append([]string(nil), connectorOriginCapabilities...),
		}})
	}))
	defer server.Close()

	client, err := newServerClient(server.URL, &testAuth{}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.issue(context.Background(), "tunnel_01", "host_01", "issue-request-01"); err != nil {
		t.Fatal(err)
	}
	requestBody := <-requestBodies
	var document struct {
		HostID       string   `json:"host_id"`
		Capabilities []string `json:"capabilities"`
		TTL          int      `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(requestBody, &document); err != nil {
		t.Fatal(err)
	}
	if document.HostID != "host_01" || document.TTL != 300 || !reflect.DeepEqual(document.Capabilities, connectorOriginCapabilities) {
		t.Fatalf("issue body=%s", requestBody)
	}
	wantBody := `{"host_id":"host_01","capabilities":["h2c","http","tcp_private","unix"],"ttl_seconds":300}`
	if !bytes.Equal(requestBody, []byte(wantBody)) {
		t.Fatalf("issue body=%s, want=%s", requestBody, wantBody)
	}
}

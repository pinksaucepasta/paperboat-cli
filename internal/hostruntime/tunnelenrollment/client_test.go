package tunnelenrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
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

func TestExchangeSendsCanonicalTokenField(t *testing.T) {
	now := time.Now().UTC()
	var requestBody []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tunnel_01/connectors/enrollments/exchange" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		var err error
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		writeEnvelope(t, w, testServerActivation(now, "tunnel_01", "connector_01", "operation_01"))
	}))
	defer server.Close()

	client, err := newServerClient(server.URL, &testAuth{}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	store := exchangeCredentialStore{}
	token := "pbce_" + strings.Repeat("t", 48)
	credential := Credential{Reference: "protected-file://paperboat/connectors/key_01", Thumbprint: "thumbprint_01", PublicKey: make([]byte, ed25519.PublicKeySize)}
	if _, err := client.exchange(context.Background(), "tunnel_01", "host_01", "exchange-request-01", token, credential, &store); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(requestBody, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["enrollment_token"]; ok {
		t.Fatalf("exchange used issue-response token field: %s", requestBody)
	}
	var gotToken string
	if err := json.Unmarshal(fields["token"], &gotToken); err != nil || gotToken != token {
		t.Fatalf("exchange token=%q err=%v body=%s", gotToken, err, requestBody)
	}
}

type exchangeCredentialStore struct{}

func (exchangeCredentialStore) CreateKey(context.Context, string) (Credential, error) {
	return Credential{}, errors.New("not used")
}
func (exchangeCredentialStore) Sign(context.Context, string, []byte) ([]byte, error) {
	return []byte("credential-proof"), nil
}
func (exchangeCredentialStore) PutEnrollmentToken(context.Context, string, string) (string, error) {
	return "", errors.New("not used")
}
func (exchangeCredentialStore) EnrollmentToken(context.Context, string) (string, error) {
	return "", errors.New("not used")
}
func (exchangeCredentialStore) DeleteEnrollmentToken(context.Context, string) error { return nil }

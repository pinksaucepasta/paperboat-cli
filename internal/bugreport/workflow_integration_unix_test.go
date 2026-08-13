//go:build darwin || linux

package bugreport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type unixDiagnosticService struct {
	bundle  diagnostics.Bundle
	markers []string
}

func (s *unixDiagnosticService) Diagnostics(context.Context) (localapi.DiagnosticSnapshot, error) {
	return localapi.DiagnosticSnapshot{Schema: localapi.DiagnosticSnapshotSchemaV1, ObservedAt: time.Now().UTC()}, nil
}
func (s *unixDiagnosticService) RecordBugreportMarker(_ context.Context, phase string) error {
	s.markers = append(s.markers, phase)
	return nil
}
func (s *unixDiagnosticService) CreateBugreport(context.Context) (diagnostics.Bundle, error) {
	return s.bundle, nil
}

func TestWorkflowAcrossLocalAndControlAPIsUploadsExactDaemonBundle(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "pb-br-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	bundleBytes := []byte("PK exact daemon bundle across APIs")
	bundlePath := filepath.Join(root, "bugreport-pb-0123456789abcdef0123456789abcdef.zip")
	if err := os.WriteFile(bundlePath, bundleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	diagnosticsService := &unixDiagnosticService{bundle: diagnostics.Bundle{Schema: diagnostics.BundleSchemaV1, Correlation: "pb-0123456789abcdef0123456789abcdef", CreatedAt: now, Path: bundlePath, Bytes: int64(len(bundleBytes)), Categories: []string{"manifest", "recent_events", "redacted_events", "status"}}}
	snapshot, _ := localapi.NewSnapshotStore(&localapi.Snapshot{Schema: localapi.SnapshotSchemaV1, Generation: 1, ObservedAt: now, DaemonState: "ready"})
	socket := filepath.Join(root, "daemon.sock")
	localServer, err := localapi.NewServer(localapi.ServerConfig{SocketPath: socket, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: snapshot, Diagnostics: diagnosticsService})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- localServer.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); ; {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local API socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	localClient, err := localapi.NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded []byte
	var controlServer *httptest.Server
	controlServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/diagnostic-upload-intents":
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Errorf("control bearer missing")
			}
			var request api.DiagnosticUploadIntentRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Bytes != int64(len(bundleBytes)) {
				t.Errorf("intent request=%#v error=%v", request, err)
			}
			writeIntegrationData(w, http.StatusCreated, api.DiagnosticUploadIntent{Schema: api.DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: request.CorrelationID, State: "pending", ExpiresAt: time.Now().UTC().Add(time.Minute), UploadMethod: http.MethodPut, UploadURL: controlServer.URL + "/object", UploadHeaders: map[string]string{"Content-Type": "application/zip", "If-None-Match": "*"}})
		case "/object":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("bearer leaked to object storage")
			}
			uploaded, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case "/v1/diagnostic-upload-intents/diag_0123456789abcdef/complete":
			writeIntegrationData(w, http.StatusOK, api.DiagnosticUploadIntent{Schema: api.DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "uploaded", ExpiresAt: time.Now().UTC().Add(time.Minute)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlServer.Close()
	controlClient := api.New(controlServer.URL, config.Credential{AccessToken: "access"}, controlServer.Client())
	result, err := Run(ctx, Options{Record: true, Upload: true, Input: bytes.NewBufferString("\n"), Prompt: io.Discard, Local: localClient, Server: controlClient})
	if err != nil {
		t.Fatal(err)
	}
	if result.Validate() != nil || !result.Uploaded || !bytes.Equal(uploaded, bundleBytes) || !slices.Equal(diagnosticsService.markers, []string{"start", "end"}) {
		t.Fatalf("result=%#v uploaded=%q markers=%v", result, uploaded, diagnosticsService.markers)
	}
	cancel()
	<-done
}

func writeIntegrationData(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
}

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestDiagnosticUploadUsesExactDirectBytesWithoutBearer(t *testing.T) {
	bundle := []byte("exact diagnostic zip bytes")
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/diagnostic-upload-intents":
			if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("Idempotency-Key") != "operation-00000001" {
				t.Errorf("control headers=%v", r.Header)
			}
			writeAPIData(t, w, http.StatusCreated, DiagnosticUploadIntent{Schema: DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "pending", ExpiresAt: time.Now().UTC().Add(10 * time.Minute), UploadMethod: http.MethodPut, UploadURL: server.URL + "/object", UploadHeaders: map[string]string{"Content-Type": "application/zip", "If-None-Match": "*"}})
		case "/object":
			if r.Header.Get("Authorization") != "" || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/zip" || r.ContentLength != int64(len(bundle)) {
				t.Errorf("object headers=%v length=%d", r.Header, r.ContentLength)
			}
			got, _ := io.ReadAll(r.Body)
			if !bytes.Equal(got, bundle) {
				t.Errorf("object bytes=%q", got)
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/diagnostic-upload-intents/diag_0123456789abcdef/complete":
			writeAPIData(t, w, http.StatusOK, DiagnosticUploadIntent{Schema: DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "uploaded", ExpiresAt: time.Now().UTC().Add(10 * time.Minute)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{AccessToken: "access-token"}, server.Client())
	intent, err := client.CreateDiagnosticUploadIntent(context.Background(), "operation-00000001", DiagnosticUploadIntentRequest{Schema: DiagnosticUploadIntentRequestSchemaV1})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UploadDiagnosticBundle(context.Background(), intent, bytes.NewReader(bundle), int64(len(bundle))); err != nil {
		t.Fatal(err)
	}
	completed, err := client.CompleteDiagnosticUploadIntent(context.Background(), intent.IntentID)
	if err != nil || completed.State != "uploaded" {
		t.Fatalf("completed=%#v error=%v", completed, err)
	}
}

func TestDiagnosticUploadRejectsRedirectAndUnsafeHeader(t *testing.T) {
	redirected := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
			return
		}
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{}, server.Client())
	base := DiagnosticUploadIntent{Schema: DiagnosticUploadIntentSchemaV1, IntentID: "diag_0123456789abcdef", CorrelationID: "pb-0123456789abcdef0123456789abcdef", State: "pending", ExpiresAt: time.Now().UTC().Add(time.Minute), UploadMethod: http.MethodPut, UploadURL: server.URL + "/redirect", UploadHeaders: map[string]string{"Content-Type": "application/zip"}}
	if err := client.UploadDiagnosticBundle(context.Background(), base, bytes.NewReader([]byte("x")), 1); err == nil || redirected {
		t.Fatalf("redirect error=%v followed=%t", err, redirected)
	}
	base.UploadURL = server.URL + "/target"
	base.UploadHeaders = map[string]string{"Authorization": "Bearer leaked"}
	if err := client.UploadDiagnosticBundle(context.Background(), base, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("unsafe header accepted")
	}
}

func writeAPIData(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{"data": value}); err != nil {
		t.Error(err)
	}
}

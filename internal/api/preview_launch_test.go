package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestMachinePreviewLaunchDescriptorRejectsWrongMachineBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"endpoint": "https://machine.test/v1/preview-launches", "machine_id": "machine_other",
			"expires_at": time.Now().Add(time.Minute), "auth": map[string]any{"method": "bearer", "token": "token"},
		}})
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{AccessToken: "access"}, server.Client())
	if _, err := client.MachinePreviewLaunchDescriptor(context.Background(), "machine_1"); err == nil || !strings.Contains(err.Error(), "invalid preview launch descriptor") {
		t.Fatalf("err=%v", err)
	}
}

func TestLaunchMachinePreviewRequiresAuthenticatedSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer launch-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input PreviewLaunchRequest
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.Name != "docs" || input.Port != 3000 || input.DurationSeconds != 60 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(PreviewRecord{PreviewKey: "p-docs", LogicalName: "docs", URL: "https://docs.preview.test", State: "active"})
	}))
	defer server.Close()
	descriptor := PreviewLaunchDescriptor{Endpoint: server.URL + "/v1/preview-launches", MachineID: "machine_1", Auth: AuthMaterial{Method: "bearer", Token: "launch-token"}}
	record, err := LaunchMachinePreview(context.Background(), descriptor, PreviewLaunchRequest{Name: "docs", Port: 3000, DurationSeconds: 60}, server.Client().Transport)
	if err != nil || record.URL != "https://docs.preview.test" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	descriptor.Auth.Token = "wrong"
	if _, err := LaunchMachinePreview(context.Background(), descriptor, PreviewLaunchRequest{Name: "docs", Port: 3000, DurationSeconds: 60}, server.Client().Transport); err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("auth err=%v", err)
	}
}

func TestLaunchMachinePreviewHonorsCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := LaunchMachinePreview(ctx, PreviewLaunchDescriptor{Endpoint: server.URL, Auth: AuthMaterial{Token: "token"}}, PreviewLaunchRequest{Name: "docs", Port: 3000, DurationSeconds: 60}, server.Client().Transport)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err=%v", err)
	}
}

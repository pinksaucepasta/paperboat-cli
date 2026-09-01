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

func TestListEnvironmentVariablesReturnsRedactedMetadataAndETag(t *testing.T) {
	updated := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/environment-variables" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"environment-global-3"`)
		writeData(w, http.StatusOK, map[string]any{
			"scope": "global", "scope_state": "active", "key_state": "ready", "version": 3, "key_epoch": 1, "manifest_id": "sha256:" + strings.Repeat("a", 64),
			"variables": []any{map[string]any{"scope": "global", "name": "API_MODE", "configured": true, "version": 3, "updated_at": updated}},
		})
	}))
	defer server.Close()

	got, err := New(server.URL, config.Credential{AccessToken: "token"}, server.Client()).ListEnvironmentVariables(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != EnvironmentVariableScopeGlobal || got.Version != 3 || got.ETag != `"environment-global-3"` || len(got.Variables) != 1 || got.Variables[0].Name != "API_MODE" || got.Variables[0].ETag != got.ETag {
		t.Fatalf("collection=%+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "value") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("metadata unexpectedly contains a value: %s", encoded)
	}
}

func TestListEnvironmentVariablesUsesMachineRouteAndRejectsUnsafeETag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/machines/mch_1/environment-variables" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"environment-machine-mch_1-4"`)
		writeData(w, http.StatusOK, map[string]any{
			"scope": "machine", "machine_id": "mch_1", "scope_state": "active", "key_state": "ready", "version": 4, "key_epoch": 2, "manifest_id": "sha256:" + strings.Repeat("b", 64),
			"status": "offline", "variables": []any{map[string]any{"scope": "machine", "machine_id": "mch_1", "name": "EMPTY_OK", "configured": true, "version": 4, "updated_at": "2026-08-31T12:00:00Z"}},
		})
	}))
	defer server.Close()
	got, err := New(server.URL, config.Credential{}, server.Client()).ListEnvironmentVariables(context.Background(), "mch_1")
	if err != nil || got.Status != "offline" || got.MachineID != "mch_1" {
		t.Fatalf("collection=%+v err=%v", got, err)
	}

	unsafe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"environment-machine-other-4"`)
		writeData(w, http.StatusOK, map[string]any{"scope": "machine", "machine_id": "mch_1", "scope_state": "active", "key_state": "ready", "version": 4, "key_epoch": 2, "manifest_id": "sha256:" + strings.Repeat("b", 64), "status": "offline", "variables": []any{}})
	}))
	defer unsafe.Close()
	if _, err := New(unsafe.URL, config.Credential{}, unsafe.Client()).ListEnvironmentVariables(context.Background(), "mch_1"); err == nil || !strings.Contains(err.Error(), "does not match scope") {
		t.Fatalf("unsafe ETag error=%v", err)
	}
}

func TestEnvironmentVariableCollectionRejectsCaseFoldedDuplicatesAndVersionMismatch(t *testing.T) {
	for _, variables := range []any{
		[]any{
			map[string]any{"scope": "global", "name": "PATH", "configured": true, "version": 2, "updated_at": "2026-08-31T12:00:00Z"},
			map[string]any{"scope": "global", "name": "path", "configured": true, "version": 2, "updated_at": "2026-08-31T12:00:00Z"},
		},
		[]any{map[string]any{"scope": "global", "name": "PATH", "configured": true, "version": 1, "updated_at": "2026-08-31T12:00:00Z"}},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("ETag", `"environment-global-2"`)
			writeData(w, http.StatusOK, map[string]any{"scope": "global", "scope_state": "active", "key_state": "ready", "version": 2, "key_epoch": 1, "manifest_id": "sha256:" + strings.Repeat("a", 64), "variables": variables})
		}))
		_, err := New(server.URL, config.Credential{}, server.Client()).ListEnvironmentVariables(context.Background(), "")
		server.Close()
		if err == nil || !strings.Contains(err.Error(), "environment-variable metadata") && !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("invalid collection accepted: %v", err)
		}
	}
	if err := validateEnvironmentVariableName("paperboat_token"); err == nil {
		t.Fatal("case-insensitive reserved name accepted")
	}
}

func TestEnvironmentVariableCollectionValidatesMachineObservationFields(t *testing.T) {
	for _, test := range []struct {
		name      string
		machineID string
		etag      string
		data      map[string]any
	}{
		{name: "global status", etag: `"environment-global-1"`, data: validEnvironmentCollectionData("", map[string]any{"status": "applied"})},
		{name: "unknown status", machineID: "mch_1", etag: `"environment-machine-mch_1-1"`, data: validEnvironmentCollectionData("mch_1", map[string]any{"status": "surprise"})},
		{name: "unknown applied state", machineID: "mch_1", etag: `"environment-machine-mch_1-1"`, data: validEnvironmentCollectionData("mch_1", map[string]any{"applied_state": "surprise"})},
		{name: "unsafe error code", machineID: "mch_1", etag: `"environment-machine-mch_1-1"`, data: validEnvironmentCollectionData("mch_1", map[string]any{"error_code": "Not-Safe"})},
		{name: "zero observed time", machineID: "mch_1", etag: `"environment-machine-mch_1-1"`, data: validEnvironmentCollectionData("mch_1", map[string]any{"observed_at": "0001-01-01T00:00:00Z"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("ETag", test.etag)
				writeData(w, http.StatusOK, test.data)
			}))
			defer server.Close()
			if _, err := New(server.URL, config.Credential{}, server.Client()).ListEnvironmentVariables(context.Background(), test.machineID); err == nil {
				t.Fatal("invalid machine observation was accepted")
			}
		})
	}
}

func validEnvironmentCollectionData(machineID string, overrides map[string]any) map[string]any {
	value := map[string]any{
		"scope": "global", "scope_state": "active", "key_state": "ready", "version": 1,
		"key_epoch": 1, "manifest_id": "sha256:" + strings.Repeat("a", 64), "variables": []any{},
	}
	if machineID != "" {
		value["scope"], value["machine_id"], value["status"] = "machine", machineID, "pending"
	}
	for key, item := range overrides {
		value[key] = item
	}
	return value
}

func TestEnvironmentVariableMetadataRejectsZeroUpdatedAt(t *testing.T) {
	if err := validateEnvironmentVariableMetadata(EnvironmentVariable{
		Scope: EnvironmentVariableScopeGlobal, Name: "API_MODE", Configured: true, Version: 1,
	}, "", "API_MODE", 1); err == nil {
		t.Fatal("zero updated_at metadata was accepted")
	}
}

func TestEnvironmentVariableCollectionAcceptsOnlyConsistentKeyState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"environment-global-0"`)
		writeData(w, http.StatusOK, map[string]any{
			"scope": "global", "key_state": "key_authorization_required", "version": 0, "variables": []any{},
		})
	}))
	defer server.Close()
	got, err := New(server.URL, config.Credential{}, server.Client()).ListEnvironmentVariables(context.Background(), "")
	if err != nil || got.KeyState != "key_authorization_required" || got.Version != 0 {
		t.Fatalf("collection=%+v err=%v", got, err)
	}

	invalid := validEnvironmentCollectionData("", map[string]any{"key_state": "ready", "manifest_id": "", "key_epoch": 0})
	if err := validateEnvironmentVariableCollection(EnvironmentVariableCollection{
		Scope:      EnvironmentVariableScopeGlobal,
		ScopeState: invalid["scope_state"].(string),
		KeyState:   invalid["key_state"].(string),
		Version:    int64(invalid["version"].(int)),
	}, ""); err == nil {
		t.Fatal("ready scope without cryptographic metadata was accepted")
	}
}

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestCreateEnvironmentKeyEnrollmentAcceptsIdempotentPendingState(t *testing.T) {
	expiresAt := time.Unix(1_800_000_000, 0).UTC()
	canonical := base64.RawURLEncoding.EncodeToString([]byte{0x81, 0x01})
	signingProof := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/environment-key-enrollments" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Cache-Control", "no-store")
		writeData(w, http.StatusOK, map[string]any{
			"schema": EnvironmentKeyEnrollmentStateSchemaV1, "request_id": "envreq_resume_1",
			"state": "pending", "expires_at": expiresAt, "safety_code": "aaaa-bbbb-cccc-dddd",
			"enrollment_request": canonical, "signing_proof": signingProof,
		})
	}))
	defer server.Close()

	signingPublic := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	recipientPublic := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	endpointCertificate := base64.RawURLEncoding.EncodeToString([]byte("certificate"))
	signingKeyID := "sigk_" + strings.Repeat("a", 43)
	state, err := New(server.URL, config.Credential{}, server.Client()).CreateEnvironmentKeyEnrollment(context.Background(), EnvironmentKeyEnrollmentRequest{
		Schema: EnvironmentKeyEnrollmentSchemaV1, OperationID: "envop_0123456789abcdef0123456789abcdef",
		SubjectKind: "manager_cli", SubjectID: "cli_1", SubjectGeneration: 1, KeyGeneration: 1,
		EndpointCertificate: &endpointCertificate, SigningPublicKey: &signingPublic, SigningKeyID: &signingKeyID,
		SigningProof: &signingProof, RecipientPublicKey: recipientPublic,
		RecipientKeyID: "envk_" + strings.Repeat("b", 43), RequestExpiresAt: expiresAt,
	})
	if err != nil || state.State != "pending" || state.Challenge != nil {
		t.Fatalf("pending enrollment state = %+v err=%v", state, err)
	}
}

func TestEnvironmentScopeInventoryIsStrictSortedMetadataOnly(t *testing.T) {
	machineID := "machine_1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/environment-scopes" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Cache-Control", "private, no-store")
		writeData(w, http.StatusOK, EnvironmentScopeInventory{
			Schema: EnvironmentScopeInventorySchemaV1,
			Scopes: []EnvironmentScopeMetadata{
				{Scope: EnvironmentVariableScopeGlobal, ScopeState: "active", Version: 2, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("a", 64), Names: []string{"APP_MODE"}},
				{Scope: EnvironmentVariableScopeMachine, MachineID: &machineID, ScopeState: "retired", Version: 4, KeyEpoch: 3, ManifestID: "sha256:" + strings.Repeat("b", 64), Names: []string{}},
			},
		})
	}))
	defer server.Close()
	inventory, err := New(server.URL, config.Credential{}, server.Client()).GetEnvironmentScopeInventory(context.Background())
	if err != nil || len(inventory.Scopes) != 2 || inventory.Scopes[1].MachineID == nil || *inventory.Scopes[1].MachineID != machineID {
		t.Fatalf("scope inventory = %+v err=%v", inventory, err)
	}

	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"data":{"schema":"paperboat.environment-scope-inventory/v1","scopes":[{"scope":"global","scope_state":"active","version":1,"key_epoch":1,"manifest_id":"sha256:` + strings.Repeat("c", 64) + `","names":[],"envelope":"must-not-be-accepted"}]}}`))
	}))
	defer invalid.Close()
	if _, err := New(invalid.URL, config.Credential{}, invalid.Client()).GetEnvironmentScopeInventory(context.Background()); err == nil {
		t.Fatal("scope inventory accepted an opaque envelope field")
	}
}

func TestEnvironmentScopeInventoryRejectsCaseInsensitiveNameCollisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeData(w, http.StatusOK, EnvironmentScopeInventory{
			Schema: EnvironmentScopeInventorySchemaV1,
			Scopes: []EnvironmentScopeMetadata{{
				Scope: EnvironmentVariableScopeGlobal, ScopeState: "active", Version: 1, KeyEpoch: 1,
				ManifestID: "sha256:" + strings.Repeat("a", 64), Names: []string{"APP_MODE", "app_mode"},
			}},
		})
	}))
	defer server.Close()
	if _, err := New(server.URL, config.Credential{}, server.Client()).GetEnvironmentScopeInventory(context.Background()); err == nil {
		t.Fatal("scope inventory accepted case-insensitive duplicate names")
	}
}

func TestEnvironmentManifestMutationCarriesOnlyOpaqueEnvelope(t *testing.T) {
	const canary = "pb-env-plaintext-canary-never-send"
	raw := []byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x40}
	envelope := base64.RawURLEncoding.EncodeToString(raw)
	manifestID := environmentDocumentID(raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/environment-manifests/machines/mch_1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("If-Match") != `"environment-machine-mch_1-7"` || r.Header.Get("If-None-Match") != "" || r.Header.Get("Idempotency-Key") != "envop_0123456789abcdef0123456789abcdef" || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("unsafe mutation headers: %#v", r.Header)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 4 || body["value"] != nil || body["values"] != nil || body["plaintext"] != nil || body["secret"] != nil || body["scope_key"] != nil || body["decryption_key"] != nil {
			t.Fatalf("mutation body has an unsafe shape: %s", mustJSON(body))
		}
		encodedBody := string(mustJSON(body))
		if strings.Contains(encodedBody, canary) {
			t.Fatal("plaintext canary reached the HTTP request body")
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("ETag", `"environment-machine-mch_1-8"`)
		writeData(w, http.StatusOK, map[string]any{
			"schema": EnvironmentManifestStateSchemaV1, "scope": "machine", "machine_id": "mch_1",
			"version": 8, "key_epoch": 2, "manifest_id": manifestID, "envelope": envelope,
		})
	}))
	defer server.Close()

	got, err := New(server.URL, config.Credential{AccessToken: "token"}, server.Client()).PutEnvironmentManifest(context.Background(), "mch_1", EnvironmentManifestMutation{
		Schema: EnvironmentManifestMutationSchemaV1, ExpectedVersion: 7,
		OperationID: "envop_0123456789abcdef0123456789abcdef", Envelope: envelope,
	}, `"environment-machine-mch_1-7"`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 8 || got.KeyEpoch != 2 || got.ManifestID != manifestID || got.ETag != `"environment-machine-mch_1-8"` {
		t.Fatalf("manifest state = %+v", got)
	}
}

func TestEnvironmentManifestGenesisUsesIfNoneMatch(t *testing.T) {
	raw := []byte{0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40}
	envelope := base64.RawURLEncoding.EncodeToString(raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "" {
			t.Fatalf("genesis headers = %#v", r.Header)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"environment-global-1"`)
		writeData(w, http.StatusOK, map[string]any{"schema": EnvironmentManifestStateSchemaV1, "scope": "global", "version": 1, "key_epoch": 1, "manifest_id": environmentDocumentID(raw), "envelope": envelope})
	}))
	defer server.Close()
	_, err := New(server.URL, config.Credential{}, server.Client()).PutEnvironmentManifest(context.Background(), "", EnvironmentManifestMutation{Schema: EnvironmentManifestMutationSchemaV1, ExpectedVersion: 0, OperationID: "envop_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Envelope: envelope}, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentManifestAndAuthorityReadsVerifyDigestETagAndNoStore(t *testing.T) {
	manifestRaw := []byte{0xd2, 0x84, 0x41, 0x01, 0xa0, 0x40, 0x40}
	authorityRaw := []byte{0xd2, 0x84, 0x41, 0x02, 0xa0, 0x40, 0x40}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/v1/environment-manifests/global":
			w.Header().Set("ETag", `"environment-global-3"`)
			writeData(w, http.StatusOK, map[string]any{"schema": EnvironmentManifestStateSchemaV1, "scope": "global", "version": 3, "key_epoch": 1, "manifest_id": environmentDocumentID(manifestRaw), "envelope": base64.RawURLEncoding.EncodeToString(manifestRaw)})
		case "/v1/environment-authority":
			authorityID := environmentDocumentID(authorityRaw)
			w.Header().Set("ETag", `"environment-authority-2-`+strings.TrimPrefix(authorityID, "sha256:")+`"`)
			writeData(w, http.StatusOK, map[string]any{"schema": EnvironmentAuthorityStateSchemaV1, "generation": 2, "authority_id": authorityID, "authority": base64.RawURLEncoding.EncodeToString(authorityRaw)})
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := New(server.URL, config.Credential{}, server.Client())
	if _, err := client.GetEnvironmentManifest(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEnvironmentAuthority(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentAuthorityDocumentsUsesExactCursorAndBounds(t *testing.T) {
	first := base64.RawURLEncoding.EncodeToString([]byte{0xd2, 0x84, 0x41, 0x01, 0xa0, 0x40, 0x40})
	second := base64.RawURLEncoding.EncodeToString([]byte{0xd2, 0x84, 0x41, 0x02, 0xa0, 0x40, 0x40})
	headID := environmentDocumentID([]byte("authority-head"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/environment-authority/documents" || r.URL.Query().Get("after_generation") != "2" || r.URL.Query().Get("after_id") != environmentDocumentID([]byte("authority-two")) {
			t.Fatalf("authority page request = %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("authority page request headers = %#v", r.Header)
		}
		w.Header().Set("Cache-Control", "no-store")
		writeData(w, http.StatusOK, map[string]any{
			"schema":              EnvironmentAuthorityPageSchemaV1,
			"authority_head":      map[string]any{"generation": 5, "authority_id": headID},
			"authority_documents": []string{first, second},
			"has_more":            true,
		})
	}))
	defer server.Close()

	page, err := New(server.URL, config.Credential{}, server.Client()).GetEnvironmentAuthorityDocuments(context.Background(), 2, environmentDocumentID([]byte("authority-two")))
	if err != nil {
		t.Fatal(err)
	}
	if page.AuthorityHead.Generation != 5 || page.AuthorityHead.AuthorityID != headID || len(page.AuthorityDocuments) != 2 || !page.HasMore {
		t.Fatalf("authority page = %+v", page)
	}
	if _, err := New(server.URL, config.Credential{}, server.Client()).GetEnvironmentAuthorityDocuments(context.Background(), 0, headID); err == nil {
		t.Fatal("generation-zero cursor accepted an authority ID")
	}
}

func TestEnvironmentE2EERejectsCacheableOrSubstitutedDataAndSanitizesErrors(t *testing.T) {
	raw := []byte{1, 2, 3}
	envelope := base64.RawURLEncoding.EncodeToString(raw)
	cacheable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"environment-global-1"`)
		writeData(w, http.StatusOK, map[string]any{"schema": EnvironmentManifestStateSchemaV1, "scope": "global", "version": 1, "key_epoch": 1, "manifest_id": environmentDocumentID(raw), "envelope": envelope})
	}))
	defer cacheable.Close()
	if _, err := New(cacheable.URL, config.Credential{}, cacheable.Client()).GetEnvironmentManifest(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "cacheable") {
		t.Fatalf("cacheable response error = %v", err)
	}

	const echoed = "ciphertext-or-secret-must-not-be-in-errors"
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "version_conflict", "message": echoed, "details": map[string]any{"envelope": echoed}}})
	}))
	defer failing.Close()
	_, err := New(failing.URL, config.Credential{}, failing.Client()).PutEnvironmentManifest(context.Background(), "", EnvironmentManifestMutation{Schema: EnvironmentManifestMutationSchemaV1, ExpectedVersion: 1, OperationID: "envop_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Envelope: envelope}, `"environment-global-1"`)
	if err == nil || strings.Contains(err.Error(), echoed) {
		t.Fatalf("unsafe error = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "version_conflict" || apiErr.Details != nil || apiErr.Message != "ENV Injection request failed" {
		t.Fatalf("sanitized error = %#v", err)
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

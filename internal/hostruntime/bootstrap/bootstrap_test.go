package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var testPublicIdentityKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))

func TestDashboardTokenPairingAndMaterialExchange(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute)
	var pairingCalls, materialCalls int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/machines/pairings":
			pairingCalls++
			var body map[string]any
			if json.NewDecoder(request.Body).Decode(&body) != nil || body["enrollment_token"] != "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP" || body["platform"] != runtime.GOOS || body["architecture"] != runtime.GOARCH || body["workspace_root"] != workspace {
				t.Fatalf("pairing body=%v", body)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": Pairing{ID: "cmp_1", UserCode: "ABCD1234", ExpiresAt: expires}})
		case "/v1/machines/pairings/installation":
			materialCalls++
			if materialCalls == 1 {
				writer.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": "user_machine_approval_pending", "message": "Machine approval is pending."}})
				return
			}
			manifest := descriptor(server.URL, "0.0.0-development")
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": Material{Schema: "paperboat.byod-installation/v1", UserMachineID: "um_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1", ControlURL: server.URL, HelperID: "helper_1", EnrollmentID: "enroll_1", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", ExpiresAt: expires, Artifact: &manifest, HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"host"}, SetupMode: "host"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	config := Config{ServerURL: server.URL, EnrollmentToken: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	pairing, err := CreatePairing(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	material, err := WaitForMaterial(context.Background(), config, pairing.ExpiresAt, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if pairingCalls != 1 || materialCalls != 2 || material.EnvironmentID != "env_1" {
		t.Fatalf("pairing=%d material=%d result=%+v", pairingCalls, materialCalls, material)
	}
}

func TestIdentityPairingDoesNotRequireEnrollmentToken(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil || body["enrollment_token"] != "" || body["public_identity_key"] != testPublicIdentityKey {
			t.Fatalf("pairing body=%v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": Pairing{ID: "cmp_identity", UserCode: "EFGH5678", ExpiresAt: expires}})
	}))
	defer server.Close()

	config := Config{ServerURL: server.URL, DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	if _, err := CreatePairing(context.Background(), config); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardEnrollmentTokenLengthContract(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil || body["enrollment_token"] != "8GXDIGUWR4E6YIGL0D6X0H3FNA" {
			t.Fatalf("pairing body=%v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": Pairing{ID: "cmp_dashboard", UserCode: "ABCD1234", ExpiresAt: expires}})
	}))
	defer server.Close()

	config := Config{ServerURL: server.URL, EnrollmentToken: "8GXDIGUWR4E6YIGL0D6X0H3FNA", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	if _, err := CreatePairing(context.Background(), config); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForMaterialStopsOnTerminalServerErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{name: "denied", status: http.StatusForbidden, code: "machine_pairing_denied", want: ErrPairingDenied},
		{name: "expired", status: http.StatusGone, code: "machine_pairing_expired", want: ErrPairingExpired},
		{name: "unavailable", status: http.StatusGone, code: "machine_installation_unavailable", want: ErrInstallationUnavailable},
		{name: "server denied", status: http.StatusForbidden, code: "user_machine_pairing_denied", want: ErrPairingDenied},
		{name: "server expired", status: http.StatusGone, code: "user_machine_pairing_expired", want: ErrPairingExpired},
		{name: "server unavailable", status: http.StatusGone, code: "user_machine_installation_unavailable", want: ErrInstallationUnavailable},
		{name: "server failure", status: http.StatusInternalServerError, code: "internal_error", want: ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls++
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": test.code, "message": "test"}})
			}))
			defer server.Close()
			config := Config{ServerURL: server.URL, EnrollmentToken: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
			_, err = WaitForMaterial(context.Background(), config, time.Now().UTC().Add(time.Minute), time.Millisecond)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestWaitForMaterialToleratesTransientNetworkErrors(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute)
	calls := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		writer.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			writer.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": "user_machine_approval_pending", "message": "Machine approval is pending."}})
		case 2:
			panic(http.ErrAbortHandler)
		default:
			manifest := descriptor(server.URL, "0.0.0-development")
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": Material{Schema: "paperboat.byod-installation/v1", UserMachineID: "um_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1", ControlURL: server.URL, HelperID: "helper_1", EnrollmentID: "enroll_1", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", ExpiresAt: expires, Artifact: &manifest, HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"host"}, SetupMode: "host"}})
		}
	}))
	defer server.Close()
	config := Config{ServerURL: server.URL, EnrollmentToken: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	material, err := WaitForMaterial(context.Background(), config, expires, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || material.EnvironmentID != "env_1" {
		t.Fatalf("requests=%d material=%+v", calls, material)
	}
}

func TestWaitForMaterialExpiresAfterTransientErrors(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer server.Close()
	config := Config{ServerURL: server.URL, EnrollmentToken: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	_, err = WaitForMaterial(context.Background(), config, time.Now().UTC().Add(40*time.Millisecond), time.Millisecond)
	if !errors.Is(err, ErrPairingExpired) {
		t.Fatalf("error = %v, want %v", err, ErrPairingExpired)
	}
}

func TestRecoverMaterialIgnoresLocalPairingExpiry(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	materialExpiry := time.Now().UTC().Add(time.Hour)
	calls := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		var body struct {
			Verifier          string `json:"verifier"`
			PublicIdentityKey string `json:"public_identity_key"`
			RuntimeEnrolled   bool   `json:"runtime_enrolled"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.Verifier != "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP" || body.PublicIdentityKey != testPublicIdentityKey || !body.RuntimeEnrolled {
			t.Fatalf("recovery body=%v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		manifest := descriptor(server.URL, "0.0.0-development")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": Material{
			Schema: "paperboat.byod-installation/v1", UserMachineID: "um_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1", ControlURL: server.URL,
			HelperID: "helper_1", EnrollmentID: "enroll_1", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", ExpiresAt: materialExpiry,
			Artifact: &manifest, HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"host"}, SetupMode: "host",
		}})
	}))
	defer server.Close()
	config := Config{ServerURL: server.URL, EnrollmentToken: "", DisplayName: "Studio", WorkspaceRoot: workspace, Verifier: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", PublicIdentityKey: testPublicIdentityKey, HTTP: server.Client()}
	material, err := RecoverMaterial(context.Background(), config, true)
	if err != nil || calls != 1 || !material.ExpiresAt.Equal(materialExpiry) {
		t.Fatalf("material=%+v requests=%d err=%v", material, calls, err)
	}
}

func TestValidateWorkspaceRejectsSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if ValidateWorkspace(link) == nil {
		t.Fatal("expected symlink workspace to be rejected")
	}
}

func TestValidateMaterialAcceptsClientCLISetup(t *testing.T) {
	material := Material{
		Schema: "paperboat.byod-installation/v1", UserMachineID: "um_1", UserMachineEnrollmentID: "ume_1",
		EnvironmentID: "env_1", ControlURL: "https://example.test", HelperID: "helper_1", EnrollmentID: "enroll_1",
		EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", ExpiresAt: time.Now().UTC().Add(time.Minute),
		Artifact:            &ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: "1.0.0", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: "https://example.test/tuf", TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH},
		HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupMode: "client", SetupRoles: []string{"interactive"},
		ClientSession: &ClientSession{Schema: "paperboat.cli-session/v1", SessionID: "cls_1", AccessToken: "access-012345678901234567890123456789", RefreshToken: "refresh-012345678901234567890123456789", TokenType: "Bearer", ExpiresIn: 3600},
	}
	if err := validateMaterial(material); err != nil {
		t.Fatalf("client material rejected: %v", err)
	}
}

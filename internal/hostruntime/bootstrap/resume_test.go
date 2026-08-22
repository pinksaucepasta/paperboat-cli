package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

func TestResumeRecordSurvivesMaterialDeliveryAndRequiresExactBinding(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2099, 8, 22, 12, 0, 0, 0, time.UTC)
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := NewResumeRecord(server, publicKey, "token-1", "Victus", "client", "verifier-012345678901234567890123456789", now.Add(time.Hour))
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadResume(root, server, publicKey, "token-1", "Victus", "client", now)
	if err != nil || loaded.Verifier != record.Verifier {
		t.Fatalf("initial resume = %#v, err=%v", loaded, err)
	}
	record.PairingStarted = true
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	// The installer may have consumed a token file before the process failed;
	// the protected local journal still permits the exact same enrollment to
	// resume without making the server replay its one-shot credential.
	if _, err := LoadResume(root, server, publicKey, "", "Victus", "client", now); err != nil {
		t.Fatalf("resume without consumed token file: %v", err)
	}
	for name, args := range map[string][]string{
		"wrong token":   {server, publicKey, "token-2", "Victus", "client"},
		"wrong machine": {server, base64.RawURLEncoding.EncodeToString(func() []byte { value := make([]byte, 32); value[0] = 1; return value }()), "token-1", "Victus", "client"},
		"wrong role":    {server, publicKey, "token-1", "Victus", "host"},
		"wrong name":    {server, publicKey, "token-1", "Other", "client"},
	} {
		if _, err := LoadResume(root, args[0], args[1], args[2], args[3], args[4], now); !errors.Is(err, ErrResumeBinding) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	material := Material{
		Schema: "paperboat.byod-installation/v1", UserMachineID: "mch_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1",
		ControlURL: server, HelperID: "helper_1", EnrollmentID: "henr_1", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP",
		ExpiresAt: now.Add(time.Hour), Artifact: &ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: "2026.08.22.22", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: server, TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH},
		HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"interactive"}, SetupMode: "client",
		ClientSession: &ClientSession{Schema: "paperboat.cli-session/v1", SessionID: "cls_1", AccessToken: "access-012345678901234567890123456789", RefreshToken: "refresh-012345678901234567890123456789", TokenType: "Bearer", ExpiresIn: 3600},
	}
	record.PairingStarted = true
	record.Material = &material
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadResume(root, server, publicKey, "token-1", "Victus", "client", now)
	if err != nil || loaded.Material == nil || loaded.Material.UserMachineID != "mch_1" {
		t.Fatalf("material resume = %#v, err=%v", loaded, err)
	}
	if err := ClearResume(root); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(root, server, publicKey, "token-1", "Victus", "client", now); !errors.Is(err, ErrResumeNotFound) {
		t.Fatalf("cleared resume error=%v", err)
	}
}

func TestTokenBackedResumeCannotDowngradeBeforePairing(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2099, 8, 22, 12, 0, 0, 0, time.UTC)
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := NewResumeRecord(server, publicKey, "token-1", "Victus", "client", "verifier-012345678901234567890123456789", now.Add(time.Hour))
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(root, server, publicKey, "", "Victus", "client", now); !errors.Is(err, ErrResumeTokenRequired) {
		t.Fatalf("pre-pair token omission error=%v", err)
	}
	record.PairingStarted = true
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(root, server, publicKey, "", "Victus", "client", now); err != nil {
		t.Fatalf("post-pair token omission should resume by verifier: %v", err)
	}
}

func TestResumeRecordRejectsTamperedOrExpiredState(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2099, 8, 22, 12, 0, 0, 0, time.UTC)
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := NewResumeRecord(server, publicKey, "token-1", "Victus", "client", "verifier-012345678901234567890123456789", now.Add(-time.Minute))
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadResume(root, server, publicKey, "token-1", "Victus", "client", now)
	if !errors.Is(err, ErrResumeExpired) {
		t.Fatalf("expired resume error=%v", err)
	}
	if loaded.Verifier != record.Verifier || loaded.PairingStarted {
		t.Fatalf("expired unpaired resume was not returned intact: %#v", loaded)
	}
	record.PairingStarted = true
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadResume(root, server, publicKey, "", "Victus", "client", now)
	if !errors.Is(err, ErrResumeExpired) || !loaded.PairingStarted || loaded.Verifier != record.Verifier {
		t.Fatalf("expired paired resume = %#v, err=%v", loaded, err)
	}
	if err := os.WriteFile(ResumePath(root), []byte(`{"schema":"paperboat.byod-resume/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(root, server, publicKey, "token-1", "Victus", "client", now.Add(-time.Hour)); !errors.Is(err, ErrResumeBinding) {
		t.Fatalf("tampered resume error=%v", err)
	}
}

func TestLoadResumeReturnsExpiredMaterialForVerifierRecovery(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	server := "https://api.example.test"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := NewResumeRecord(server, publicKey, "token-1", "Victus", "client", "verifier-012345678901234567890123456789", now.Add(-time.Hour))
	record.PairingStarted = true
	record.Material = &Material{
		Schema: "paperboat.byod-installation/v1", UserMachineID: "mch_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1",
		ControlURL: server, HelperID: "helper_1", EnrollmentID: "henr_1", EnrollmentCredential: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP",
		ExpiresAt: now.Add(-time.Minute), Artifact: &ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: "2026.08.22.22", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: server, TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH},
		HelperListenAddress: "127.0.0.1:38080", InstallationGeneration: 1, SetupRoles: []string{"interactive"}, SetupMode: "client",
		ClientSession: &ClientSession{Schema: "paperboat.cli-session/v1", SessionID: "cls_1", AccessToken: "access-012345678901234567890123456789", RefreshToken: "refresh-012345678901234567890123456789", TokenType: "Bearer", ExpiresIn: 3600},
	}
	// SaveResume deliberately rejects expired material. Write an otherwise valid
	// historical journal to exercise the loader's recovery behavior.
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureResumeDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(ResumePath(root), encoded, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadResume(root, server, publicKey, "", "Victus", "client", now)
	if !errors.Is(err, ErrResumeExpired) || loaded.Material == nil || loaded.Material.UserMachineID != "mch_1" {
		t.Fatalf("expired material resume = %#v, err=%v", loaded, err)
	}
}

func TestRecoveredMaterialCannotChangeBoundMachine(t *testing.T) {
	previous := Material{UserMachineID: "mch_1", UserMachineEnrollmentID: "ume_1", EnvironmentID: "env_1", HelperID: "helper_1", InstallationGeneration: 7, SetupMode: "client", ControlURL: "https://api.example.test"}
	recovered := previous
	if err := ValidateRecoveredMaterial(previous, recovered, true); err != nil {
		t.Fatal(err)
	}
	recovered.HelperID = "helper_rotated"
	if err := ValidateRecoveredMaterial(previous, recovered, false); err != nil {
		t.Fatalf("not-yet-enrolled helper rotation error=%v", err)
	}
	if err := ValidateRecoveredMaterial(previous, recovered, true); !errors.Is(err, ErrResumeBinding) {
		t.Fatalf("persisted helper rotation error=%v", err)
	}
	recovered = previous
	recovered.UserMachineID = "mch_other"
	if err := ValidateRecoveredMaterial(previous, recovered, true); !errors.Is(err, ErrResumeBinding) {
		t.Fatalf("changed machine error=%v", err)
	}
}

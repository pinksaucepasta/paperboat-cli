//go:build windows

package bootstrap

import (
	"encoding/base64"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

func TestSaveResumeAcceptsRealShapedWindowsClientMaterial(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	server := "https://api.pprbt.dev"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := NewResumeRecord(server, publicKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", "victus-e2e", "client", "verifier-012345678901234567890123456789", now.Add(15*time.Minute))
	record.PairingStarted = true
	record.Material = &Material{
		Schema:                  "paperboat.byod-installation/v1",
		UserMachineID:           "mch_716e2e",
		UserMachineEnrollmentID: "ume_716e2e",
		EnvironmentID:           "env_716e2e",
		ControlURL:              server,
		HelperID:                "hlp_716e2e",
		EnrollmentID:            "henr_716e2e",
		EnrollmentCredential:    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP",
		ExpiresAt:               now.Add(10 * time.Minute),
		Artifact:                &ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: "2026.08.22.23", Platform: "windows", Architecture: runtime.GOARCH, RepositoryURL: "https://get.pprbt.dev/tuf", TargetPath: releaseindex.AssetName("windows", runtime.GOARCH)},
		HelperListenAddress:     "127.0.0.1:38080",
		InstallationGeneration:  8,
		SetupRoles:              []string{"interactive"},
		SetupMode:               "client",
		ClientSession:           &ClientSession{Schema: "paperboat.cli-session/v1", SessionID: "cls_716e2e", AccessToken: "access-012345678901234567890123456789", RefreshToken: "refresh-012345678901234567890123456789", TokenType: "Bearer", ExpiresIn: 3600, Scope: "account:read"},
	}
	if err := SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadResume(root, server, publicKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP", record.DisplayName, record.SetupMode, now)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Material == nil || loaded.Material.SetupMode != "client" || loaded.Material.ClientSession == nil || loaded.Material.Artifact.Platform != "windows" {
		t.Fatalf("loaded material = %#v", loaded.Material)
	}
}

//go:build windows && paperboat_native_e2e

package hostinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

// TestNativeLegacyOwnerFullSecurityMigration proves the one supported legacy
// transition against real NTFS ACLs. The fixture is isolated from the machine
// installation but reproduces the old owner-FULL root, config, and token.
func TestNativeLegacyOwnerFullSecurityMigration(t *testing.T) {
	if !isAdministrator() {
		t.Skip("native legacy security migration requires an elevated Windows runner")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current Windows SID: %v", err)
	}
	ownerSID := user.User.Sid.String()
	previousRoot := windowsProgramDataRoot
	windowsProgramDataRoot = filepath.Join(t.TempDir(), "Paperboat")
	t.Cleanup(func() { windowsProgramDataRoot = previousRoot })

	if err := os.MkdirAll(WindowsProgramDataRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	config := WindowsRuntimeConfig{
		Schema: windowsConfigSchema, OwnerSID: ownerSID, User: "native-fixture",
		StateRoot: filepath.Join(WindowsProgramDataRoot(), "user-state"), Workspace: filepath.Join(WindowsProgramDataRoot(), "workspace"),
		ControlURL: "https://api.pprbt.dev", ListenAddress: "127.0.0.1:8080", MachineID: "native-legacy-security-fixture", SetupMode: "client",
		TokenFile: WindowsHostdTokenPath(), InstalledAt: time.Now().UTC(), Committed: true,
		Artifact: bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: "2026.08.23.1", Platform: "windows", Architecture: runtime.GOARCH, RepositoryURL: "https://get.pprbt.dev", TargetPath: "pb-windows-" + runtime.GOARCH},
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WindowsInstallConfigPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WindowsHostdTokenPath(), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyFile := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ownerSID + ")"
	legacyRoot := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ownerSID + ")"
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := applyWindowsDACL(path, legacyFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyWindowsDACL(WindowsProgramDataRoot(), legacyRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWindowsRuntimeConfig(); err == nil {
		t.Fatal("legacy owner-FULL installation was accepted before migration")
	}
	attacker := config
	attacker.OwnerSID = "S-1-5-18"
	attackerBody, err := json.Marshal(attacker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WindowsInstallConfigPath(), attackerBody, 0o600); err != nil {
		t.Fatal(err)
	}
	attackerFile := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-18)"
	attackerRoot := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-18)"
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := applyWindowsDACL(path, attackerFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyWindowsDACL(WindowsProgramDataRoot(), attackerRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateLegacyWindowsRuntimeSecurity(); err == nil {
		t.Fatal("legacy owner-FULL bytes selected a Windows identity other than the elevated repair caller")
	}
	if err := os.WriteFile(WindowsInstallConfigPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := applyWindowsDACL(path, legacyFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyWindowsDACL(WindowsProgramDataRoot(), legacyRoot); err != nil {
		t.Fatal(err)
	}

	migrated, err := migrateLegacyWindowsRuntimeSecurity()
	if err != nil {
		t.Fatalf("migrate legacy security: %v", err)
	}
	if !reflect.DeepEqual(migrated, config) {
		t.Fatalf("migration changed trusted configuration\n got: %+v\nwant: %+v", migrated, config)
	}
	currentFile := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;" + ownerSID + ")"
	currentRoot := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + ownerSID + ")"
	if !windowssecurity.ProtectedDACLMatches(WindowsInstallConfigPath(), currentFile) || !windowssecurity.ProtectedDACLMatches(WindowsHostdTokenPath(), currentFile) || !windowssecurity.ProtectedDACLMatches(WindowsProgramDataRoot(), currentRoot) {
		t.Fatal("migration did not replace every legacy owner-FULL ACL with the read-only owner contract")
	}
}

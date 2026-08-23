//go:build windows && paperboat_native_e2e

package hostinstall

import (
	"encoding/json"
	"errors"
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

	trustedOwner, err := windowsRuntimeTrustedOwner()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), ownerSID); err != nil {
		t.Fatalf("atomically create trusted machine root: %v", err)
	}
	if !windowsRuntimeSecurityMatches(WindowsProgramDataRoot(), trustedOwner, windowsRuntimeCurrentRootDACL(ownerSID)) {
		t.Fatal("new machine root was visible without its final SYSTEM owner and protected DACL")
	}
	if err := os.Remove(WindowsProgramDataRoot()); err != nil {
		t.Fatalf("reset machine-root transition fixture: %v", err)
	}
	if err := os.Mkdir(WindowsProgramDataRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	currentRootDACL := windowsRuntimeCurrentRootDACL(ownerSID)
	if err := applyWindowsOwnedDACL(WindowsProgramDataRoot(), administrators, currentRootDACL); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), ownerSID); err != nil {
		t.Fatalf("resume exact trusted machine-root transition: %v", err)
	}
	if !windowsRuntimeSecurityMatches(WindowsProgramDataRoot(), trustedOwner, currentRootDACL) {
		t.Fatal("resumed machine root did not reach its final SYSTEM-owned state")
	}
	if err := os.Remove(WindowsProgramDataRoot()); err != nil {
		t.Fatalf("reset hostile machine-root transition fixture: %v", err)
	}
	if err := os.Mkdir(WindowsProgramDataRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	hostileTransitionDACL := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if err := applyWindowsOwnedDACL(WindowsProgramDataRoot(), administrators, hostileTransitionDACL); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsMachineDirectory(WindowsProgramDataRoot(), ownerSID); err == nil {
		t.Fatal("Administrators-owned root with a noncanonical DACL was accepted as a resumable transition")
	}
	if !windowssecurity.OwnerMatchesSID(WindowsProgramDataRoot(), administrators) || !windowssecurity.ProtectedDACLMatches(WindowsProgramDataRoot(), hostileTransitionDACL) {
		t.Fatal("rejected machine-root transition was mutated")
	}
	if err := os.Remove(WindowsProgramDataRoot()); err != nil {
		t.Fatalf("reset atomic machine-root fixture: %v", err)
	}
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
		if err := applyWindowsOwnedDACL(path, user.User.Sid, legacyFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyWindowsOwnedDACL(WindowsProgramDataRoot(), user.User.Sid, legacyRoot); err != nil {
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
		if err := applyWindowsOwnedDACL(path, user.User.Sid, legacyFile); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyWindowsOwnedDACL(WindowsProgramDataRoot(), user.User.Sid, legacyRoot); err != nil {
		t.Fatal(err)
	}

	foreignOwner, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []struct{ name, path, dacl string }{
		{"root", WindowsProgramDataRoot(), legacyRoot},
		{"config", WindowsInstallConfigPath(), legacyFile},
		{"token", WindowsHostdTokenPath(), legacyFile},
	} {
		t.Run("foreign_owner_"+hostile.name, func(t *testing.T) {
			if err := applyWindowsOwnedDACL(hostile.path, foreignOwner, hostile.dacl); err != nil {
				t.Fatalf("install hostile owner: %v", err)
			}
			before := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath())
			if _, err := migrateLegacyWindowsRuntimeSecurity(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("foreign-owned %s returned %v, want invalid request", hostile.name, err)
			}
			after := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath())
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("foreign-owned %s failure mutated runtime security\n before: %v\n  after: %v", hostile.name, before, after)
			}
			if err := applyWindowsOwnedDACL(hostile.path, user.User.Sid, hostile.dacl); err != nil {
				t.Fatalf("restore legacy owner: %v", err)
			}
		})
	}

	currentFile := windowsRuntimeCurrentFileDACL(ownerSID)
	currentRoot := windowsRuntimeCurrentRootDACL(ownerSID)
	objects := []struct{ name, path, legacy, current string }{
		{"token", WindowsHostdTokenPath(), legacyFile, currentFile},
		{"config", WindowsInstallConfigPath(), legacyFile, currentFile},
		{"root", WindowsProgramDataRoot(), legacyRoot, currentRoot},
	}
	for _, object := range objects {
		for _, crossed := range []struct {
			name  string
			owner *windows.SID
			dacl  string
		}{
			{"legacy_owner_current_dacl", user.User.Sid, object.current},
			{"trusted_owner_legacy_dacl", trustedOwner, object.legacy},
		} {
			t.Run("crossed_pair_"+object.name+"_"+crossed.name, func(t *testing.T) {
				resetNativeLegacyRuntimeSecurity(t, user.User.Sid, legacyRoot, legacyFile)
				if err := applyWindowsOwnedDACL(object.path, crossed.owner, crossed.dacl); err != nil {
					t.Fatalf("install crossed owner/DACL pair: %v", err)
				}
				before := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath())
				if _, err := migrateLegacyWindowsRuntimeSecurity(); !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("crossed %s pair returned %v, want invalid request", object.name, err)
				}
				after := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath())
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("crossed %s pair failure mutated runtime security", object.name)
				}
			})
		}
	}

	for _, crash := range []struct {
		name         string
		currentPaths []string
	}{
		{"after_token", []string{WindowsHostdTokenPath()}},
		{"after_token_and_config", []string{WindowsHostdTokenPath(), WindowsInstallConfigPath()}},
	} {
		t.Run("resume_"+crash.name, func(t *testing.T) {
			resetNativeLegacyRuntimeSecurity(t, user.User.Sid, legacyRoot, legacyFile)
			for _, path := range crash.currentPaths {
				if err := applyWindowsOwnedDACL(path, trustedOwner, currentFile); err != nil {
					t.Fatalf("prepare crash cut: %v", err)
				}
			}
			migrated, err := migrateLegacyWindowsRuntimeSecurity()
			if err != nil {
				t.Fatalf("migrate legacy security: %v", err)
			}
			if !reflect.DeepEqual(migrated, config) {
				t.Fatalf("migration changed trusted configuration\n got: %+v\nwant: %+v", migrated, config)
			}
			if !windowssecurity.ProtectedDACLMatches(WindowsInstallConfigPath(), currentFile) || !windowssecurity.ProtectedDACLMatches(WindowsHostdTokenPath(), currentFile) || !windowssecurity.ProtectedDACLMatches(WindowsProgramDataRoot(), currentRoot) {
				t.Fatal("migration did not replace every legacy owner-FULL ACL with the read-only owner contract")
			}
			for _, path := range []string{WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
				if !windowssecurity.OwnerMatchesSID(path, trustedOwner) {
					t.Fatalf("migration did not transfer %s to the trusted filesystem owner", path)
				}
			}
			before := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath())
			if _, err := migrateLegacyWindowsRuntimeSecurity(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("fully current state returned %v, want invalid request", err)
			}
			if after := nativeWindowsSecuritySnapshot(t, WindowsProgramDataRoot(), WindowsInstallConfigPath(), WindowsHostdTokenPath()); !reflect.DeepEqual(after, before) {
				t.Fatal("fully current migration rejection mutated runtime security")
			}
		})
	}
}

func resetNativeLegacyRuntimeSecurity(t *testing.T, owner *windows.SID, rootDACL, fileDACL string) {
	t.Helper()
	for _, path := range []string{WindowsInstallConfigPath(), WindowsHostdTokenPath()} {
		if err := applyWindowsOwnedDACL(path, owner, fileDACL); err != nil {
			t.Fatalf("reset legacy file security: %v", err)
		}
	}
	if err := applyWindowsOwnedDACL(WindowsProgramDataRoot(), owner, rootDACL); err != nil {
		t.Fatalf("reset legacy root security: %v", err)
	}
}

func nativeWindowsSecuritySnapshot(t *testing.T, paths ...string) []string {
	t.Helper()
	result := make([]string, len(paths))
	for index, path := range paths {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || descriptor == nil {
			t.Fatalf("read %s security: %v", path, err)
		}
		result[index] = descriptor.String()
	}
	return result
}

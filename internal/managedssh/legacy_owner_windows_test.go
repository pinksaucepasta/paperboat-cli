//go:build windows

package managedssh

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestWindowsManagedSSHDefaultAdministratorsOwnerAndRestartMigration(t *testing.T) {
	home := managedSSHWindowsTestHome(t)
	publicKey := authorizedPublicLine(t)
	config := managedSSHWindowsTestConfig(home)

	withAdministratorsDefaultOwner(t, func() error {
		if err := InstallManagedIdentityPublicKey(home, 0, publicKey); err != nil {
			return err
		}
		_, err := InstallOpenSSHConfig(config)
		return err
	})
	assertWindowsManagedSSHStateOwner(t, home, currentWindowsUserSID(t))

	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsManagedSSHStateOwner(t, home, administrators)
	if err := ValidateInstalledOpenSSHConfig(home, 0, config.AliasSuffix, config.AgentSocket); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("Administrators-owned state validation error=%v", err)
	}

	// StartManagedSSH installs the identity first and OpenSSH config second on
	// every daemon start. The first install must repair the complete exact
	// legacy state before normal owner-strict reads resume.
	withAdministratorsDefaultOwner(t, func() error {
		if err := InstallManagedIdentityPublicKey(home, 0, publicKey); err != nil {
			return err
		}
		_, err := InstallOpenSSHConfig(config)
		return err
	})
	if err := ValidateManagedIdentityPublicKey(home, 0, publicKey); err != nil {
		t.Fatalf("validate identity after restart migration: %v", err)
	}
	if err := ValidateInstalledOpenSSHConfig(home, 0, config.AliasSuffix, config.AgentSocket); err != nil {
		t.Fatalf("validate OpenSSH config after restart migration: %v", err)
	}
	assertWindowsManagedSSHStateOwner(t, home, currentWindowsUserSID(t))
}

func TestWindowsManagedSSHLegacyMigrationRejectsForeignOwnerBeforeMutation(t *testing.T) {
	home, publicKey := createWindowsManagedSSHState(t)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsManagedSSHStateOwner(t, home, administrators)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsOwner(t, filepath.Join(home, ".ssh", "paperboat_config"), system)

	withAdministratorsDefaultOwnerError(t, func() error {
		return InstallManagedIdentityPublicKey(home, 0, publicKey)
	}, ErrOpenSSHConfigConflict)
	if !windowsOwnerMatches(filepath.Join(home, ".ssh", "config"), administrators) {
		t.Fatal("migration changed a file before rejecting the foreign owner")
	}
}

func TestWindowsManagedSSHLegacyMigrationRejectsHardLinkedStateBeforeMutation(t *testing.T) {
	home, publicKey := createWindowsManagedSSHState(t)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsManagedSSHStateOwner(t, home, administrators)
	identity := filepath.Join(home, ".ssh", ManagedIdentityPublicKeyFilename)
	if err := os.Link(identity, identity+".link"); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	withAdministratorsDefaultOwnerError(t, func() error {
		return InstallManagedIdentityPublicKey(home, 0, publicKey)
	}, ErrOpenSSHConfigConflict)
	if !windowsOwnerMatches(filepath.Join(home, ".ssh", "config"), administrators) {
		t.Fatal("migration changed a file before rejecting the hard link")
	}
}

func TestWindowsManagedSSHLegacyMigrationRejectsNonExactDACLBeforeMutation(t *testing.T) {
	home, publicKey := createWindowsManagedSSHState(t)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsManagedSSHStateOwner(t, home, administrators)
	path := filepath.Join(home, ".ssh", "paperboat_config")
	setWindowsDACL(t, path, managedSSHSDDL(currentWindowsUserSID(t).String())+"(A;;FR;;;WD)")

	withAdministratorsDefaultOwnerError(t, func() error {
		return InstallManagedIdentityPublicKey(home, 0, publicKey)
	}, ErrOpenSSHConfigConflict)
	if !windowsOwnerMatches(filepath.Join(home, ".ssh", "config"), administrators) {
		t.Fatal("migration changed a file before rejecting the non-exact DACL")
	}
}

func createWindowsManagedSSHState(t *testing.T) (string, string) {
	t.Helper()
	home := managedSSHWindowsTestHome(t)
	publicKey := authorizedPublicLine(t)
	if err := InstallManagedIdentityPublicKey(home, 0, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallOpenSSHConfig(managedSSHWindowsTestConfig(home)); err != nil {
		t.Fatal(err)
	}
	return home, publicKey
}

func managedSSHWindowsTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	user := currentWindowsUserSID(t)
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(home, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user, nil, nil, nil)
	}); err != nil {
		t.Skipf("setting an exact Windows test-home owner requires SeRestorePrivilege: %v", err)
	}
	return home
}

func managedSSHWindowsTestConfig(home string) OpenSSHConfig {
	return OpenSSHConfig{
		Home:              home,
		AliasSuffix:       "pprbt",
		ProxyCommand:      `"C:\Program Files\Paperboat\bin\pb.exe" __ssh-proxy --host %h --port %p --user %r`,
		KnownHostsCommand: `"C:\Program Files\Paperboat\bin\pb.exe" __ssh-known-hosts --host %h --port %p`,
		AgentSocket:       `\\.\pipe\paperboat-ssh-agent-test`,
		IdentityFile:      ManagedIdentityPublicKeyPath(home),
		Targets:           []OpenSSHAliasTarget{{Alias: "hn", DisplayName: "hn", User: "root", Port: 22}},
	}
}

func currentWindowsUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		t.Fatal(err)
	}
	return user.User.Sid
}

func withAdministratorsDefaultOwner(t *testing.T, operation func() error) {
	t.Helper()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	member, err := windows.GetCurrentProcessToken().IsMember(administrators)
	if err != nil || !member {
		t.Skip("Administrators-default-owner regression requires an elevated administrator token")
	}
	if err := windowssecurity.WithRestorePrivilegeAndOwner(administrators, operation); err != nil {
		t.Fatal(err)
	}
}

func withAdministratorsDefaultOwnerError(t *testing.T, operation func() error, want error) {
	t.Helper()
	var operationErr error
	withAdministratorsDefaultOwner(t, func() error {
		operationErr = operation()
		return nil
	})
	if !errors.Is(operationErr, want) {
		t.Fatalf("operation error=%v, want %v", operationErr, want)
	}
}

func setWindowsManagedSSHStateOwner(t *testing.T, home string, owner *windows.SID) {
	t.Helper()
	for _, name := range []string{"config", "paperboat_config", ".paperboat-config-install-v1.json", ManagedIdentityPublicKeyFilename} {
		setWindowsOwner(t, filepath.Join(home, ".ssh", name), owner)
	}
}

func setWindowsOwner(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	}); err != nil {
		t.Fatal(err)
	}
}

func setWindowsDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func assertWindowsManagedSSHStateOwner(t *testing.T, home string, owner *windows.SID) {
	t.Helper()
	sid := owner.String()
	for _, name := range []string{"config", "paperboat_config", ".paperboat-config-install-v1.json", ManagedIdentityPublicKeyFilename} {
		path := filepath.Join(home, ".ssh", name)
		if !windowsOwnerMatches(path, owner) {
			t.Errorf("%s owner is not %s", name, sid)
		}
		if err := verifyManagedSSHACL(path, sid); err != nil {
			t.Errorf("%s owner/DACL verification: %v", name, err)
		}
	}
}

func windowsOwnerMatches(path string, owner *windows.SID) bool {
	return windowssecurity.OwnerMatchesSID(path, owner)
}

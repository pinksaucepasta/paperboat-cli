//go:build windows

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func changeFixtureOwnerToAdministrators(t *testing.T, path string) *windows.SID {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current owner: %v", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if administrators.Equals(user.User.Sid) {
		t.Skip("current SID already equals the hostile owner fixture SID")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, administrators, nil, nil, nil); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("changing the fixture owner requires an elevated native runner: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil)
	})
	return administrators
}

func preparePrivateWindowsCredentialDirectory(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	directory, err := dpapiCredentialDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	setWindowsFixtureSecurity(t, directory, owner, sddl, true)
	if !credentialFilePrivate(directory) {
		t.Fatal("credential parent fixture is not current-user owned and protected")
	}
	return directory, sddl
}

func setWindowsFixtureSecurity(t *testing.T, path string, owner *windows.SID, sddl string, protected bool) {
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
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		securityInformation = windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInformation, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(absolute)
}

func makeWindowsNetworkTokenDirectoryFixture(t *testing.T, path string, extraACE bool) *windows.SID {
	t.Helper()
	administrators := changeFixtureOwnerToAdministrators(t, path)
	sddl := "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;S-1-5-5-0-424242)"
	if extraACE {
		sddl += "(A;;FR;;;WD)"
	}
	setWindowsFixtureSecurity(t, path, administrators, sddl, false)
	return administrators
}

func TestWindowsCredentialTargetUsesPrivateNamespace(t *testing.T) {
	if got, want := windowsCredentialTarget("access-token-v1-123"), "paperboat:access-token-v1-123"; got != want {
		t.Fatalf("credential target = %q, want %q", got, want)
	}
}

func TestWindowsCredentialReadWithoutLogonSessionIsAbsentLegacySource(t *testing.T) {
	if err := windowsCredentialReadError(windows.ERROR_NO_SUCH_LOGON_SESSION); !errors.Is(err, ErrSecretNotFound) || errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("network-logon legacy read error = %v", err)
	}
	if err := windowsCredentialReadError(windows.ERROR_ACCESS_DENIED); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("access-denied legacy read error = %v", err)
	}
}

func TestWindowsFileFallbackIsDPAPIProtected(t *testing.T) {
	directory := t.TempDir()
	store := FileSecretStore{Dir: directory}
	ref, secret := "fallback-native", "must-not-appear-in-plaintext-नौका"
	if err := store.Set(ref, secret); err != nil {
		t.Fatalf("set protected fallback: %v", err)
	}
	body, err := os.ReadFile(store.path(ref))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Fatal("protected credential contains plaintext")
	}
	actual, err := store.Get(ref)
	if err != nil || actual != secret {
		t.Fatalf("get protected fallback = %q, %v", actual, err)
	}
}

func TestWindowsDPAPIAuthorityRoundTrip(t *testing.T) {
	ref := fmt.Sprintf("native-test-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	for _, value := range []string{"paperboat windows credential", "Unicode: नौका 🚤"} {
		if err := store.Set(ref, value); err != nil {
			t.Fatalf("set credential: %v", err)
		}
		actual, err := store.Get(ref)
		if err != nil || actual != value {
			t.Fatalf("get credential = %q, %v; want %q", actual, err, value)
		}
		path, _, err := dpapiSecretPath(ref)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		header := keyringDPAPIV2Header(ref, false)
		if err != nil || !bytes.HasPrefix(body, header) || bytes.Contains(body, []byte(value)) {
			t.Fatalf("credential is not a sealed machine-scope v2 envelope: header=%x err=%v", body[:min(len(body), len(header))], err)
		}
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	if _, err := store.Get(ref); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("read deleted credential: %v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func cleanupWindowsKeyringFixture(ref string) {
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err == nil {
		_, _, _ = procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), windowsCredentialTypeGeneric, 0)
	}
	_ = deleteDPAPISecret(ref)
}

func TestWindowsDeleteWithoutLogonSessionCommitsTombstone(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ref := fmt.Sprintf("native-delete-no-logon-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWindowsKeyringFixture(ref) })
	store := KeyringStore{}
	if err := store.Set(ref, "authoritative-secret"); err != nil {
		t.Fatal(err)
	}
	// Preserve a real legacy value to prove that the tombstone, rather than
	// absence of a migration source, prevents resurrection.
	writeLegacyWindowsCredential(t, ref, "stale-legacy-secret")
	noLogonDelete := func(*uint16) (uintptr, error) {
		return 0, windows.ERROR_NO_SUCH_LOGON_SESSION
	}
	if err := deleteWindowsCredential(ref, noLogonDelete); err != nil {
		t.Fatalf("delete without Credential Manager logon session: %v", err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, keyringDPAPITombstone(ref)) || bytes.Contains(body, []byte("authoritative-secret")) {
		t.Fatalf("deletion authority is not the exact ref-bound tombstone: body=%x err=%v", body, err)
	}
	if !credentialFilePrivate(path) {
		t.Fatal("deletion tombstone does not have the exact credential owner and ACL")
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("tombstoned credential returned value=%q error=%v", value, err)
	}
	if err := deleteWindowsCredential(ref, noLogonDelete); err != nil {
		t.Fatalf("idempotent delete without Credential Manager logon session: %v", err)
	}

	// An interactive retry removes both the planted legacy value and marker.
	if err := store.Delete(ref); err != nil {
		t.Fatalf("interactive deletion retry: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tombstone remained after completed legacy cleanup: %v", err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("deleted credential returned value=%q error=%v", value, err)
	}
}

func TestWindowsDeleteLegacyCompletionRemovesTombstone(t *testing.T) {
	for _, test := range []struct {
		name   string
		result uintptr
		err    error
	}{
		{name: "deleted", result: 1},
		{name: "not-found", err: windows.ERROR_NOT_FOUND},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", t.TempDir())
			ref := fmt.Sprintf("native-delete-complete-%s-%d", test.name, time.Now().UnixNano())
			t.Cleanup(func() { cleanupWindowsKeyringFixture(ref) })
			if err := (KeyringStore{}).Set(ref, "delete-me"); err != nil {
				t.Fatal(err)
			}
			if err := deleteWindowsCredential(ref, func(*uint16) (uintptr, error) {
				return test.result, test.err
			}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			path, _, err := dpapiSecretPath(ref)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("DPAPI deletion marker remained: %v", err)
			}
		})
	}
}

func TestWindowsDeleteUncertainLegacyFailureStaysTombstoned(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ref := fmt.Sprintf("native-delete-uncertain-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupWindowsKeyringFixture(ref) })
	store := KeyringStore{}
	if err := store.Set(ref, "old-authority"); err != nil {
		t.Fatal(err)
	}
	err := deleteWindowsCredential(ref, func(*uint16) (uintptr, error) {
		return 0, windows.ERROR_ACCESS_DENIED
	})
	if !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("uncertain legacy cleanup error=%v", err)
	}
	path, _, pathErr := dpapiSecretPath(ref)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(body, keyringDPAPITombstone(ref)) {
		t.Fatalf("uncertain cleanup did not retain tombstone: body=%x err=%v", body, readErr)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("uncertain tombstoned credential returned value=%q error=%v", value, err)
	}
	if err := store.Set(ref, "explicit-new-authority"); err != nil {
		t.Fatalf("replace tombstone: %v", err)
	}
	if value, err := store.Get(ref); value != "explicit-new-authority" || err != nil {
		t.Fatalf("replacement authority value=%q error=%v", value, err)
	}
}

func TestWindowsDPAPITombstoneIsBoundToReference(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ref := fmt.Sprintf("native-delete-bound-%d", time.Now().UnixNano())
	otherRef := ref + "-other"
	t.Cleanup(func() {
		cleanupWindowsKeyringFixture(ref)
		cleanupWindowsKeyringFixture(otherRef)
	})
	if err := setDPAPISecretTombstone(ref); err != nil {
		t.Fatal(err)
	}
	if err := (KeyringStore{}).Set(otherRef, "placeholder"); err != nil {
		t.Fatal(err)
	}
	otherPath, _, err := dpapiSecretPath(otherRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, keyringDPAPITombstone(ref), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := (KeyringStore{}).Get(otherRef); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) || errors.Is(err, errDPAPISecretDeleted) {
		t.Fatalf("wrong-ref tombstone returned value=%q error=%v", value, err)
	}
}

func TestWindowsDPAPIV2RejectsTamperWrongScopeAndWrongRef(t *testing.T) {
	store := KeyringStore{}
	ref := fmt.Sprintf("native-v2-tamper-%d", time.Now().UnixNano())
	otherRef := ref + "-other"
	t.Cleanup(func() {
		_ = store.Delete(ref)
		_ = store.Delete(otherRef)
	})
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	wrongScope := append([]byte(nil), original...)
	wrongScope[5] = 2
	if err := os.WriteFile(path, wrongScope, 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("wrong-scope envelope returned value=%q error=%v", value, err)
	}

	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) || errors.Is(err, ErrCredentialRequiresInteractiveLogin) {
		t.Fatalf("tampered v2 envelope returned value=%q error=%v", value, err)
	}

	if err := store.Set(otherRef, "placeholder"); err != nil {
		t.Fatal(err)
	}
	otherPath, _, err := dpapiSecretPath(otherRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(otherRef); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("wrong-ref envelope returned value=%q error=%v", value, err)
	}
}

func TestWindowsLegacyUserScopeDPAPIIsMigratedToMachineScopeV2(t *testing.T) {
	store := KeyringStore{}
	ref := fmt.Sprintf("native-v1-migration-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "placeholder"); err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{1}, []byte("legacy-user-scope-secret")...)
	protected, err := dpapiTransform(plain, true)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, protected, 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); err != nil || value != "legacy-user-scope-secret" {
		t.Fatalf("legacy migration value=%q error=%v", value, err)
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(body, keyringDPAPIV2Header(ref, false)) {
		t.Fatalf("legacy credential was not rewritten as v2 machine scope: err=%v", err)
	}
}

func TestWindowsLegacyLayoutHardensOwnerRootAndMigrates(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	ref := fmt.Sprintf("native-v1-layout-%d", time.Now().UnixNano())
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(directory)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{1}, []byte("legacy-layout-secret")...)
	protected, err := dpapiTransform(plain, true)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	if err := atomicfile.Write(path, protected, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		t.Fatal(err)
	}
	if credentialFilePrivate(root) {
		t.Fatal("old-layout fixture unexpectedly started with a hardened Paperboat root")
	}
	if value, err := (KeyringStore{}).Get(ref); err != nil || value != "legacy-layout-secret" {
		t.Fatalf("old-layout migration value=%q error=%v", value, err)
	}
	if !credentialFilePrivate(root) {
		t.Fatal("owner-owned old-layout Paperboat root was not hardened during migration")
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(body, keyringDPAPIV2Header(ref, false)) {
		t.Fatalf("old-layout credential was not rewritten as v2: %v", err)
	}
}

func TestWindowsUnreadableLegacyDPAPIRequiresInteractiveLogin(t *testing.T) {
	store := KeyringStore{}
	ref := fmt.Sprintf("native-v1-login-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "placeholder"); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("legacy-user-scope-ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialRequiresInteractiveLogin) || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("unreadable legacy credential returned value=%q error=%v", value, err)
	}
}

func TestWindowsMachineScopeCredentialMigratesTrustedAdministratorsOwnedDirectory(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store := KeyringStore{}
	ref := fmt.Sprintf("native-trusted-legacy-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	_, directory, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	changeFixtureOwnerToAdministrators(t, directory)
	if value, err := store.Get(ref); value != "machine-secret" || err != nil {
		t.Fatalf("trusted legacy credential directory returned value=%q error=%v", value, err)
	}
	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.OwnerMatchesSID(directory, owner) || !credentialFilePrivate(directory) {
		t.Fatal("trusted legacy credential directory was not migrated to the current owner and protected ACL")
	}
}

func TestWindowsMachineScopeCredentialMigratesTrustedAdministratorsOwnedFile(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store := KeyringStore{}
	ref := fmt.Sprintf("native-trusted-legacy-file-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	changeFixtureOwnerToAdministrators(t, path)
	if value, err := store.Get(ref); value != "machine-secret" || err != nil {
		t.Fatalf("trusted legacy credential file returned value=%q error=%v", value, err)
	}
	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.OwnerMatchesSID(path, owner) || !credentialFilePrivate(path) {
		t.Fatal("trusted legacy credential file was not migrated to the current owner and protected ACL")
	}
}

func TestWindowsCredentialChildCreatedWithNetworkTokenDefaultsIsSecured(t *testing.T) {
	directory, sddl := preparePrivateWindowsCredentialDirectory(t)
	path := filepath.Join(directory, "profiles")
	created := false
	err := ensureDPAPIDirectoryWithCreate(path, sddl, func(parent windows.Handle, path, sddl string) (windows.Handle, windows.ByHandleFileInformation, string, error) {
		created = true
		handle, information, finalPath, err := createDPAPIDirectoryHandle(parent, path, sddl)
		if err != nil {
			return 0, windows.ByHandleFileInformation{}, "", err
		}
		makeWindowsNetworkTokenDirectoryFixture(t, path, false)
		return handle, information, finalPath, nil
	})
	if err != nil {
		t.Fatalf("secure newly created network-token directory: %v", err)
	}
	if !created {
		t.Fatal("network-token creation fixture was not used")
	}
	if !credentialFilePrivate(path) {
		t.Fatal("new network-token directory was not secured to the current user")
	}
}

func TestWindowsCredentialLegacyNetworkDirectoriesMigrateUnderPrivateParent(t *testing.T) {
	for _, name := range []string{"pending-revocations", "transactions"} {
		t.Run(name, func(t *testing.T) {
			directory, sddl := preparePrivateWindowsCredentialDirectory(t)
			path := filepath.Join(directory, name)
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			makeWindowsNetworkTokenDirectoryFixture(t, path, false)
			if err := ensureDPAPIDirectory(path, sddl); err != nil {
				t.Fatalf("migrate %s network-token directory: %v", name, err)
			}
			if !credentialFilePrivate(path) {
				t.Fatalf("%s network-token directory was not migrated to the current user", name)
			}
		})
	}
}

func TestWindowsCredentialLegacyNetworkDirectoryRejectsExtraACE(t *testing.T) {
	directory, sddl := preparePrivateWindowsCredentialDirectory(t)
	path := filepath.Join(directory, "pending-revocations")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	administrators := makeWindowsNetworkTokenDirectoryFixture(t, path, true)
	if err := ensureDPAPIDirectory(path, sddl); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("network-token directory with extra ACE error=%v", err)
	}
	if !windowssecurity.OwnerMatchesSID(path, administrators) {
		t.Fatal("rejected network-token directory owner was changed")
	}
}

func TestWindowsCredentialLegacyNetworkDirectoryDoesNotBroadenRootMigration(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	path := filepath.Join(localAppData, "Paperboat")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	administrators := makeWindowsNetworkTokenDirectoryFixture(t, path, false)
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDPAPIDirectory(path, sddl); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("network-token Paperboat root error=%v", err)
	}
	if !windowssecurity.OwnerMatchesSID(path, administrators) {
		t.Fatal("rejected network-token Paperboat root owner was changed")
	}
}

func TestWindowsMachineScopeCredentialRejectsAdministratorsOwnedFileWithExtraACE(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store := KeyringStore{}
	ref := fmt.Sprintf("native-hostile-legacy-file-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	administrators := changeFixtureOwnerToAdministrators(t, path)
	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + owner.String() + ")(A;;FR;;;WD)")
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
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("Administrators-owned credential with extra ACE returned value=%q error=%v", value, err)
	}
	if !windowssecurity.OwnerMatchesSID(path, administrators) {
		t.Fatal("rejected credential file owner was mutated")
	}
}

func TestWindowsMachineScopeSetDoesNotMutateForeignOwnedDirectory(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	directory := filepath.Join(localAppData, "Paperboat", "credentials")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignOwner := changeFixtureOwnerToAdministrators(t, directory)
	ref := fmt.Sprintf("native-foreign-precreate-%d", time.Now().UnixNano())
	if err := (KeyringStore{}).Set(ref, "machine-secret"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("foreign-owned precreated directory Set error=%v", err)
	}
	if !windowssecurity.OwnerMatchesSID(directory, foreignOwner) {
		t.Fatal("Set changed the foreign-owned credential directory owner")
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Set created a credential in foreign-owned state: %v", err)
	}
}

func TestWindowsMachineScopeSetDoesNotMutateForeignOwnedRoot(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	root := filepath.Join(localAppData, "Paperboat")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	foreignOwner := changeFixtureOwnerToAdministrators(t, root)
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	setWindowsFixtureSecurity(t, root, foreignOwner, sddl+"(A;;FR;;;WD)", true)
	ref := fmt.Sprintf("native-foreign-root-%d", time.Now().UnixNano())
	if err := (KeyringStore{}).Set(ref, "machine-secret"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("foreign-owned precreated root Set error=%v", err)
	}
	if !windowssecurity.OwnerMatchesSID(root, foreignOwner) {
		t.Fatal("Set changed the foreign-owned credential root owner")
	}
	_, directory, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Set created a directory below foreign-owned state: %v", err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("must-not-be-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := (KeyringStore{}).Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("foreign-owned root Get returned value=%q error=%v", value, err)
	}
	if !windowssecurity.OwnerMatchesSID(root, foreignOwner) {
		t.Fatal("Get changed the foreign-owned credential root owner")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "must-not-be-read" {
		t.Fatalf("Get mutated the foreign-owned credential: body=%q error=%v", body, err)
	}
}

func TestWindowsMachineScopeGetRejectsReparseRoot(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	target := t.TempDir()
	targetRoot := filepath.Join(target, "Paperboat")
	directory := filepath.Join(targetRoot, "credentials")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(localAppData, "Paperboat")
	if err := os.Symlink(targetRoot, root); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skipf("creating the hostile reparse fixture requires an elevated native runner: %v", err)
		}
		t.Fatal(err)
	}
	ref := fmt.Sprintf("native-reparse-root-%d", time.Now().UnixNano())
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("must-not-be-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := (KeyringStore{}).Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("reparse-root credential returned value=%q error=%v", value, err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "must-not-be-read" {
		t.Fatalf("reparse-root fixture was mutated: body=%q error=%v", body, err)
	}
}

func TestWindowsDPAPIAuthorityRejectsEmptyCredential(t *testing.T) {
	ref := fmt.Sprintf("native-empty-%d", time.Now().UnixNano())
	store := KeyringStore{}
	if err := store.Set(ref, ""); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("empty credential error = %v", err)
	}
	if _, err := store.Get(ref); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("empty credential was persisted: %v", err)
	}
}

func writeLegacyWindowsCredential(t *testing.T, ref, value string) {
	t.Helper()
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	username, err := windowsUTF16(keyringService)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte(value)
	defer clear(blob)
	credential := windowsCredential{Type: windowsCredentialTypeGeneric, TargetName: target, CredentialBlobSize: uint32(len(blob)), Persist: windowsCredentialPersistLocalMachine, UserName: username}
	if len(blob) > 0 {
		credential.CredentialBlob = &blob[0]
	}
	if result, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0); result == 0 {
		t.Fatalf("write legacy Credential Manager value: %v", callErr)
	}
}

func TestWindowsCredentialFallsBackAcrossCredentialManagerContexts(t *testing.T) {
	ref := fmt.Sprintf("native-context-fallback-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "owner-scoped-secret"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	result, _, callErr := procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), windowsCredentialTypeGeneric, 0)
	if result == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		t.Fatalf("remove Credential Manager copy: %v", callErr)
	}
	actual, err := store.Get(ref)
	if err != nil || actual != "owner-scoped-secret" {
		t.Fatalf("DPAPI fallback = %q, %v", actual, err)
	}
}

func TestWindowsLegacyCredentialManagerReadBackfillsDPAPI(t *testing.T) {
	ref := fmt.Sprintf("native-legacy-migration-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	writeLegacyWindowsCredential(t, ref, "legacy-secret")
	actual, err := store.Get(ref)
	if err != nil || actual != "legacy-secret" {
		t.Fatalf("legacy Credential Manager read = %q, %v", actual, err)
	}
	if migrated, err := getDPAPISecret(ref, nil); err != nil || migrated != actual {
		t.Fatalf("migrated DPAPI value = %q, %v", migrated, err)
	}
	target, err := windowsUTF16(windowsCredentialTarget(ref))
	if err != nil {
		t.Fatal(err)
	}
	var credential *windowsCredential
	result, _, callErr := procCredReadW.Call(uintptr(unsafe.Pointer(target)), windowsCredentialTypeGeneric, 0, uintptr(unsafe.Pointer(&credential)))
	if result != 0 {
		procCredFree.Call(uintptr(unsafe.Pointer(credential)))
		t.Fatal("legacy Credential Manager value remained after migration")
	}
	if !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		t.Fatalf("read migrated Credential Manager value: %v", callErr)
	}
}

func TestWindowsCredentialManagerCannotReplaceInvalidDPAPIAuthority(t *testing.T) {
	ref := fmt.Sprintf("native-invalid-authority-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "authoritative-secret"); err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsCredential(t, ref, "stale-legacy-secret")
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("invalid DPAPI authority returned value=%q error=%v", value, err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "corrupt" {
		t.Fatalf("invalid DPAPI authority was overwritten: body=%q error=%v", body, err)
	}
}

func TestWindowsLegacyEmptyCredentialIsNotMigrated(t *testing.T) {
	ref := fmt.Sprintf("native-empty-legacy-%d", time.Now().UnixNano())
	store := KeyringStore{}
	t.Cleanup(func() { _ = store.Delete(ref) })
	writeLegacyWindowsCredential(t, ref, "")
	if _, err := store.Get(ref); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("empty legacy credential error = %v", err)
	}
	if _, err := getDPAPISecret(ref, nil); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("empty legacy credential was migrated: %v", err)
	}
}

func TestWindowsCredentialErrorClassification(t *testing.T) {
	if err := windowsCredentialError("read", windows.ERROR_NOT_FOUND); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("not-found error = %v, want ErrSecretNotFound", err)
	}
	if err := windowsCredentialError("read", windows.ERROR_ACCESS_DENIED); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("service error = %v, want ErrCredentialStoreUnavailable", err)
	}
}

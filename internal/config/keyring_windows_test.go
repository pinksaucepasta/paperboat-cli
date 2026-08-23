//go:build windows

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func TestWindowsCredentialTargetUsesPrivateNamespace(t *testing.T) {
	if got, want := windowsCredentialTarget("access-token-v1-123"), "paperboat:access-token-v1-123"; got != want {
		t.Fatalf("credential target = %q, want %q", got, want)
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

func TestWindowsMachineScopeCredentialRejectsForeignOwnedDirectory(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store := KeyringStore{}
	ref := fmt.Sprintf("native-foreign-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	_, directory, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	changeFixtureOwnerToAdministrators(t, directory)
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("foreign-owned credential directory returned value=%q error=%v", value, err)
	}
}

func TestWindowsMachineScopeCredentialRejectsForeignOwnedFile(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store := KeyringStore{}
	ref := fmt.Sprintf("native-foreign-file-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = store.Delete(ref) })
	if err := store.Set(ref, "machine-secret"); err != nil {
		t.Fatal(err)
	}
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		t.Fatal(err)
	}
	changeFixtureOwnerToAdministrators(t, path)
	if value, err := store.Get(ref); value != "" || !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("foreign-owned credential file returned value=%q error=%v", value, err)
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

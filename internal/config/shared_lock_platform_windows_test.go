//go:build windows

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestSharedLockCreatesProtectedOwnerAndLockMetadata(t *testing.T) {
	// t.TempDir itself may be BA-owned when this native test is launched
	// through elevated SSH. Create the profile root with the same explicit
	// owner path as production before exercising missing lock parents.
	root := filepath.Join(t.TempDir(), "secure-root")
	if err := createSharedLockDirectory(root); err != nil {
		t.Fatal(err)
	}
	lock := newSharedLock(filepath.Join(root, "profiles", "profile.json.lock"))
	if err := lock.Lock(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Unlock(); err != nil {
			t.Error(err)
		}
	}()

	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(lock.path), lock.path} {
		handle, err := openSharedLockDirectory(path, false)
		if err != nil {
			t.Fatalf("open protected lock directory %s: %v", path, err)
		}
		if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
			t.Errorf("lock directory %s owner is not the stable user SID", path)
		}
		if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
			t.Errorf("lock directory %s DACL is not the exact protected credential DACL", path)
		}
		windows.CloseHandle(handle)
	}

	ownerPath := filepath.Join(lock.path, "owner.json")
	pathUTF16, err := windows.UTF16PtrFromString(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pathUTF16, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		t.Fatal(err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || information.NumberOfLinks != 1 {
		t.Fatalf("owner metadata has unsafe file attributes: %#x", information.FileAttributes)
	}
	if !windowssecurity.HandleOwnerMatchesSID(handle, owner) {
		t.Fatal("owner metadata owner is not the stable user SID")
	}
	if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		t.Fatal("owner metadata DACL is not the exact protected credential DACL")
	}
	if _, err := os.Stat(ownerPath); err != nil {
		t.Fatal(err)
	}
}

func TestPendingRevocationMutationMigratesLegacyNetworkDirectoryBeforeLock(t *testing.T) {
	credentialDirectory, sddl := preparePrivateWindowsCredentialDirectory(t)
	store := ProfileStore{Path: credentialDirectory}
	record := PendingRevocation{
		Version:            ProfileVersion,
		Issuer:             "https://api.example.com",
		CLIClientSessionID: "cls_native_legacy_pending",
		RefreshSecretRef:   "revocation-native-legacy-pending-refresh",
		CreatedAt:          time.Now().UTC(),
	}
	pendingDirectory := filepath.Join(credentialDirectory, "pending-revocations")
	if err := ensureDPAPIDirectory(pendingDirectory, sddl); err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := store.pendingRevocationPath(record.Issuer, record.CLIClientSessionID)
	if err := atomicWrite(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	makeWindowsNetworkTokenDirectoryFixture(t, pendingDirectory, false)
	updated, err := store.MarkRevocationSucceeded(record)
	if err != nil {
		t.Fatalf("mark revocation beneath legacy network-token directory: %v", err)
	}
	if !updated.ServerRevoked {
		t.Fatal("revocation was not marked as server-revoked")
	}
	if !credentialFilePrivate(pendingDirectory) {
		t.Fatal("legacy network-token pending directory was not migrated before locking")
	}
	if _, err := os.Lstat(newSharedLock(path + ".lock").path); !os.IsNotExist(err) {
		t.Fatalf("pending record lock remained after mutation: %v", err)
	}
}

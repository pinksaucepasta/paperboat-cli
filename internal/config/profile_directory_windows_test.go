//go:build windows

package config

import (
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestEnsureProfileDirectoryProtectsCredentialNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials", "profiles")
	if err := ensureProfileDirectory(path); err != nil {
		t.Fatal(err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	if !windowssecurity.ProtectedDACLMatches(path, descriptor.String()) {
		t.Fatalf("profile directory does not have the protected current-user DACL: %s", descriptor.String())
	}
}

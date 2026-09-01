//go:build windows

package updated

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTRK28WindowsArchitectureSelectionAcceptsAMD64AndARM64Only(t *testing.T) {
	baseline := testWindowsUpdaterConfig(t)
	for _, test := range []struct {
		architecture string
		valid        bool
	}{
		{architecture: "amd64", valid: true},
		{architecture: "arm64", valid: true},
		{architecture: "386"},
		{architecture: "arm"},
		{architecture: ""},
	} {
		config := baseline
		config.Architecture = test.architecture
		if got := validWindowsConfig(config); got != test.valid {
			t.Fatalf("architecture %q valid=%t want=%t", test.architecture, got, test.valid)
		}
	}
}

func TestTRK28WindowsRecoveryUsesExactARM64RollbackSlot(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current", "pb.exe")
	rollback := filepath.Join(root, "rollback", "pb.exe")
	if err := os.MkdirAll(filepath.Dir(current), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rollback), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollback, []byte("signed arm64 rollback"), 0o700); err != nil {
		t.Fatal(err)
	}
	var verifiedPath, verifiedArchitecture string
	verify := func(_ context.Context, path, architecture string) error {
		verifiedPath, verifiedArchitecture = path, architecture
		return nil
	}
	restore, err := validateWindowsSlot(context.Background(), current, rollback, "arm64", verify)
	if err != nil || !restore {
		t.Fatalf("restore=%t err=%v", restore, err)
	}
	if verifiedPath != rollback || verifiedArchitecture != "arm64" {
		t.Fatalf("verified path=%q architecture=%q", verifiedPath, verifiedArchitecture)
	}
}

func TestTRK28WindowsRecoveryNeverRestoresUnverifiedOrTruncatedRollback(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current", "pb.exe")
	rollback := filepath.Join(root, "rollback", "pb.exe")
	if err := os.MkdirAll(filepath.Dir(rollback), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollback, []byte("truncated"), 0o700); err != nil {
		t.Fatal(err)
	}
	verifyErr := errors.New("signature or hash mismatch")
	verify := func(_ context.Context, path, architecture string) error {
		if path != rollback || architecture != "arm64" {
			t.Fatalf("verification input path=%q architecture=%q", path, architecture)
		}
		return verifyErr
	}
	restore, err := validateWindowsSlot(context.Background(), current, rollback, "arm64", verify)
	if restore || !errors.Is(err, verifyErr) {
		t.Fatalf("unverified rollback restore=%t err=%v", restore, err)
	}
	if _, err := os.Stat(current); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current slot changed after failed verification: %v", err)
	}
}

func TestTRK28WindowsRecoveryVerifiesCurrentBeforeKeepingIt(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current", "pb.exe")
	rollback := filepath.Join(root, "rollback", "pb.exe")
	if err := os.MkdirAll(filepath.Dir(current), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("signed current"), 0o700); err != nil {
		t.Fatal(err)
	}
	var verified []string
	verify := func(_ context.Context, path, architecture string) error {
		verified = append(verified, path+"|"+architecture)
		return nil
	}
	restore, err := validateWindowsSlot(context.Background(), current, rollback, "amd64", verify)
	if err != nil || restore || !reflect.DeepEqual(verified, []string{current + "|amd64"}) {
		t.Fatalf("restore=%t err=%v verified=%q", restore, err, verified)
	}
}

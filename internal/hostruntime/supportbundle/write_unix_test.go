//go:build !windows

package supportbundle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteParentSyncFailureRetainsPublishedOutputAndCleansTemporary(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	output := filepath.Join(directory, "support-bundle.json")
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	builder.syncParent = func(parent string) error {
		if parent != directory {
			t.Fatalf("sync parent = %q, want %q", parent, directory)
		}
		return errors.New("injected directory sync failure")
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorWriteFailed {
		t.Fatalf("Write error = %v", err)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(written) != string(preview.Bytes()) {
		t.Fatal("published output changed after directory sync failure")
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWritePinsVerifiedParentAcrossAdversarialSwap(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	originalParent := filepath.Join(directory, "original")
	movedParent := filepath.Join(directory, "moved")
	attackerParent := filepath.Join(directory, "attacker")
	if err := os.Mkdir(originalParent, 0o700); err != nil {
		t.Fatalf("Mkdir original: %v", err)
	}
	if err := os.Mkdir(attackerParent, 0o700); err != nil {
		t.Fatalf("Mkdir attacker: %v", err)
	}

	output := filepath.Join(originalParent, "support-bundle.json")
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	builder.beforePublish = func(string) error {
		if err := os.Rename(originalParent, movedParent); err != nil {
			return err
		}
		return os.Symlink(attackerParent, originalParent)
	}
	if _, err := builder.Write(t.Context(), preview, output); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(attackerParent, "support-bundle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle published through swapped parent: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(movedParent, "support-bundle.json"))
	if err != nil || string(written) != string(preview.Bytes()) {
		t.Fatalf("pinned-parent output = %q, %v", written, err)
	}
	assertNoTemporaryFiles(t, movedParent)
}

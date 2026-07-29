package filetransfer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareAcceptsArbitraryAndEmptyFilesThroughOneDescriptor(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "empty"), filepath.Join(root, "archive.bin")}
	if err := os.WriteFile(paths[0], nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	batch, err := Prepare(paths, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	if len(batch.Sources) != 2 || batch.Sources[0].Size != 0 || batch.Sources[1].Size != 4 || batch.Sources[0].Basename != "empty" {
		t.Fatalf("sources=%#v", batch.Sources)
	}
	if err := os.Remove(paths[1]); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement")
	if err := os.WriteFile(paths[1], replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := batch.Sources[1].Reader.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != string([]byte{0, 1, 2, 3}) {
		t.Fatalf("descriptor changed: %q", buffer)
	}
}

func TestPrepareRejectsRelativeTraversalSymlinkDeviceAndLimits(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "link")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		paths  []string
		limits Limits
	}{
		{"relative", []string{"regular"}, Limits{}}, {"traversal", []string{root + string(filepath.Separator) + "x" + string(filepath.Separator) + ".." + string(filepath.Separator) + "regular"}, Limits{}}, {"symlink", []string{symlink}, Limits{}}, {"directory", []string{root}, Limits{}}, {"size", []string{regular}, Limits{MaxFileBytes: 3}}, {"count", []string{regular, regular}, Limits{MaxBatchFiles: 1}}, {"batch", []string{regular}, Limits{MaxBatchBytes: 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if batch, err := Prepare(test.paths, test.limits); err == nil {
				_ = batch.Close()
				t.Fatal("accepted invalid source")
			}
		})
	}
}

func TestNewBatchIDIsUniquePerAction(t *testing.T) {
	first, err := NewBatchID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewBatchID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != len("fb_")+32 || first[:3] != "fb_" {
		t.Fatalf("batch IDs %q and %q", first, second)
	}
}

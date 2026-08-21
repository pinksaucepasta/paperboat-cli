//go:build windows

package diagnostics

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsDiskRingAndBundleUseCurrentUserACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Paperboat diagnostics")
	config := DiskConfig{
		Directory:     filepath.Join(root, "events"),
		MaximumBytes:  2 * MaximumRecordBytes,
		SegmentBytes:  MaximumRecordBytes,
		QueueCapacity: 8,
		Retention:     time.Hour,
	}
	ring, err := NewDiskRing(config)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := resolveDiagnosticOwner(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiagnosticDirectory(config.Directory, owner); err != nil {
		t.Fatalf("events directory ACL: %v", err)
	}
	event, err := NewEvent(time.Now().UTC(), "daemon", "state_changed", "info", map[string]string{"state": "ready"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Record(event); err != nil {
		t.Fatal(err)
	}
	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := ring.ReadAll(context.Background(), config.MaximumBytes)
	if err != nil || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("data=%q err=%v", data, err)
	}
	entries, err := os.ReadDir(config.Directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	segment := filepath.Join(config.Directory, entries[0].Name())
	if _, err := verifiedDiagnosticFile(segment, owner); err != nil {
		t.Fatalf("segment ACL/reparse validation: %v", err)
	}
	recorder, err := NewRecorder(DiskConfig{Directory: filepath.Join(root, "bundle-events"), QueueCapacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record("daemon", "lifecycle", "info", map[string]string{"state": "ready"}); err != nil {
		t.Fatal(err)
	}
	bundle, err := CreateBundle(context.Background(), BundleConfig{
		Directory: root,
		Recorder:  recorder,
		Status:    json.RawMessage(`{"schema":"paperboat.status/v1","state":"ready"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle validation: %v", err)
	}
	if _, err := verifiedDiagnosticFile(bundle.Path, owner); err != nil {
		t.Fatalf("bundle ACL/reparse validation: %v", err)
	}
	archive, err := zip.OpenReader(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if len(archive.File) != 4 {
		t.Fatalf("bundle entries=%d", len(archive.File))
	}
}

func TestWindowsDiagnosticOwnerMustMatchCurrentUser(t *testing.T) {
	if _, err := resolveDiagnosticOwner(DiskConfig{OwnerSID: "S-1-5-19"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("owner mismatch err=%v", err)
	}
}

func TestWindowsDiagnosticsRejectReparseDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symbolic-link creation unavailable: %v", err)
	}
	if _, err := NewDiskRing(DiskConfig{Directory: link}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reparse directory err=%v", err)
	}
}

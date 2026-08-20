//go:build !windows

package diagnostics

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEvent(t *testing.T, sequence string) Event {
	t.Helper()
	event, err := NewEvent(time.Date(2026, 8, 4, 1, 2, 3, 0, time.UTC), "daemon", "state_changed", "info", map[string]string{"generation": sequence, "state": "ready"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestEventRejectsUnsafeOrContentBearingFields(t *testing.T) {
	for _, fields := range []map[string]string{
		{"token": "secret"},
		{"path": "workspace"},
		{"state": "/home/user"},
		{"state": "contains spaces"},
		{"state": "line\nbreak"},
	} {
		if _, err := NewEvent(time.Now().UTC(), "daemon", "state_changed", "info", fields); !errors.Is(err, ErrInvalid) {
			t.Fatalf("fields=%v err=%v", fields, err)
		}
	}
	event := testEvent(t, "1")
	encoded, err := json.Marshal(event)
	if err != nil || strings.Contains(string(encoded), "token") || strings.Contains(string(encoded), "path") {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}

func TestMemoryRingIsConcurrentBoundedAndCloned(t *testing.T) {
	ring := &MemoryRing{}
	event := testEvent(t, "g")
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for index := 0; index < 100; index++ {
				_ = ring.Record(event)
			}
		}(worker)
	}
	group.Wait()
	events := ring.Snapshot()
	if len(events) != MemoryCapacity {
		t.Fatalf("events=%d", len(events))
	}
	events[0].Fields["state"] = "changed"
	if ring.Snapshot()[0].Fields["state"] != "ready" {
		t.Fatal("memory snapshot shared mutable fields")
	}
}

func TestDiskRingPersistsOwnerOnlyRecordsAndRecoversPartialTail(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "diagnostics")
	config := DiskConfig{Directory: directory, OwnerUID: os.Geteuid(), MaximumBytes: 2 * MaximumRecordBytes, SegmentBytes: MaximumRecordBytes, QueueCapacity: 8, Retention: time.Hour}
	ring, err := NewDiskRing(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Record(testEvent(t, "1")); err != nil || ring.Record(testEvent(t, "2")) != nil || ring.Close() != nil {
		t.Fatal(err)
	}
	data, err := ring.ReadAll(context.Background(), config.MaximumBytes)
	if err != nil || bytesLines(data) != 2 {
		t.Fatalf("lines=%d err=%v data=%s", bytesLines(data), err, data)
	}
	entries, _ := os.ReadDir(directory)
	path := filepath.Join(directory, entries[0].Name())
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%#v err=%v", info, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(`{"schema":"paperboat.diagnostic-event/v1"`)
	_ = file.Close()
	recovered, err := NewDiskRing(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = recovered.ReadAll(context.Background(), config.MaximumBytes)
	if err != nil || bytesLines(data) != 2 {
		t.Fatalf("recovered lines=%d err=%v data=%s", bytesLines(data), err, data)
	}
}

func TestDiskRingRejectsUnsafeFilesystemAndExpiresOldSegments(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskRing(DiskConfig{Directory: unsafe, OwnerUID: os.Geteuid()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("permissive directory err=%v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskRing(DiskConfig{Directory: link, OwnerUID: os.Geteuid()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink directory err=%v", err)
	}
	directory := filepath.Join(root, "ring")
	now := time.Date(2026, 8, 4, 1, 0, 0, 0, time.UTC)
	config := DiskConfig{Directory: directory, OwnerUID: os.Geteuid(), MaximumBytes: MaximumRecordBytes, SegmentBytes: MaximumRecordBytes, QueueCapacity: 1, Retention: time.Hour, Clock: func() time.Time { return now }}
	ring, err := NewDiskRing(config)
	if err != nil {
		t.Fatal(err)
	}
	_ = ring.Record(testEvent(t, "1"))
	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(directory)
	path := filepath.Join(directory, entries[0].Name())
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	ring, err = NewDiskRing(config)
	if err != nil {
		t.Fatal(err)
	}
	_ = ring.Close()
	entries, _ = os.ReadDir(directory)
	if len(entries) != 0 {
		t.Fatalf("expired entries=%v", entries)
	}
}

func TestBundleIsRedactedBoundedOwnerOnlyAndCorrelated(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "diagnostics")
	recorder, err := NewRecorder(DiskConfig{Directory: filepath.Join(directory, "events"), OwnerUID: os.Geteuid(), QueueCapacity: 8})
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record("daemon", "lifecycle", "info", map[string]string{"state": "ready"}); err != nil {
		t.Fatal(err)
	}
	bundle, err := CreateBundle(context.Background(), BundleConfig{Directory: directory, OwnerUID: os.Geteuid(), Recorder: recorder, Status: json.RawMessage(`{"schema":"paperboat.status/v1","state":"ready"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Schema != BundleSchemaV1 || !strings.HasPrefix(bundle.Correlation, "pb-") || bundle.Bytes <= 0 || bundle.Bytes > MaximumBundleBytes {
		t.Fatalf("bundle=%#v", bundle)
	}
	info, err := os.Stat(bundle.Path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() != bundle.Bytes {
		t.Fatalf("bundle info=%#v err=%v", info, err)
	}
	archive, err := zip.OpenReader(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	seen := map[string]bool{}
	for _, file := range archive.File {
		seen[file.Name] = true
		if strings.Contains(file.Name, "/") || file.Name == "" {
			t.Fatalf("unsafe bundle entry %q", file.Name)
		}
	}
	for _, name := range []string{"manifest.json", "recent-events.ndjson", "events.ndjson", "status.json"} {
		if !seen[name] {
			t.Fatalf("missing bundle category %q", name)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
}

func bytesLines(data []byte) int { return strings.Count(string(data), "\n") }

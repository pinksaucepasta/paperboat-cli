package releaseeligibility

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

func testDeferral(t *testing.T) releasepolicy.Deferral {
	t.Helper()
	plan, err := releasepolicy.Default("2026.08.31.9", strings.Repeat("a", 64), 3, "routine", "seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	deferral, err := plan.GrantDeferral(releasepolicy.DeferralRequest{Version: plan.Version, RequestedSecs: 3600, Reason: "maintenance"}, time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return deferral
}

func TestFileStoreRoundTripIsBoundedAndPrivate(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(filepath.Join(directory, "deferral.json"))
	if err != nil {
		t.Fatal(err)
	}
	requireUsableStoreTestPath(t, store)
	deferral := testDeferral(t)
	if err := store.Save(context.Background(), deferral); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o, want 0600", info.Mode().Perm())
	}
	got, present, err := store.CurrentDeferral(context.Background())
	if err != nil || !present || got != deferral {
		t.Fatalf("got=%+v present=%v err=%v", got, present, err)
	}
	if err := store.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.CurrentDeferral(context.Background()); err != nil || present {
		t.Fatalf("after remove present=%v err=%v", present, err)
	}
}

func TestFileStoreRejectsMalformedDuplicateTrailingAndOversized(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(filepath.Join(directory, "deferral.json"))
	if err != nil {
		t.Fatal(err)
	}
	requireUsableStoreTestPath(t, store)
	valid, err := testDeferral(t).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "duplicate", body: strings.TrimSpace(string(valid))[:len(strings.TrimSpace(string(valid)))-1] + `,"version":"2026.08.31.9"}`},
		{name: "unknown", body: strings.TrimSpace(string(valid))[:len(strings.TrimSpace(string(valid)))-1] + `,"extra":true}`},
		{name: "trailing", body: strings.TrimSpace(string(valid)) + ` {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(store.Path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, present, err := store.CurrentDeferral(context.Background()); !errors.Is(err, ErrInvalidRecord) || present {
				t.Fatalf("present=%v err=%v", present, err)
			}
		})
	}
	if err := os.WriteFile(store.Path, bytesOfSize(MaxDeferralBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.CurrentDeferral(context.Background()); !errors.Is(err, ErrRecordTooLarge) || present {
		t.Fatalf("oversized present=%v err=%v", present, err)
	}
}

func TestFileStoreRejectsSymlinkAndCanceledOperations(t *testing.T) {
	directory := t.TempDir()
	store, err := NewFileStore(filepath.Join(directory, "deferral.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.Path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, present, err := store.CurrentDeferral(context.Background()); !errors.Is(err, ErrUnsafePath) || present {
		t.Fatalf("symlink present=%v err=%v", present, err)
	}
	_ = os.Remove(store.Path)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Save(canceled, testDeferral(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("save canceled err=%v", err)
	}
}

func TestFileStoreRejectsUnsafePaths(t *testing.T) {
	for _, path := range []string{"", "relative.json", "/tmp/../tmp/deferral.json", "/"} {
		if _, err := NewFileStore(path); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("path=%q err=%v", path, err)
		}
	}
}

func bytesOfSize(size int64) []byte {
	return make([]byte, int(size))
}

//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func TestValidRuntimeIdentitySupportsOnlyExactPairs(t *testing.T) {
	for _, test := range []struct {
		uid, gid int
		want     bool
	}{
		{uid: 1000, gid: 1000, want: true},
		{uid: 0, gid: 0, want: true},
		{uid: 0, gid: 1000},
		{uid: 1000, gid: 0},
		{uid: -1, gid: -1},
	} {
		if got := validRuntimeIdentity(test.uid, test.gid); got != test.want {
			t.Fatalf("validRuntimeIdentity(%d, %d)=%v want %v", test.uid, test.gid, got, test.want)
		}
	}
}

func TestResolveUpdatedActiveRecoversVerifiedMonitoringCandidate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	version := "2026.08.27.55"
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-monitor", Stage: updateflow.StageMonitoring,
		ActiveVersion: "2026.08.27.52", CandidateVersion: version,
		CandidateDigest: strings.Repeat("a", 64), CandidateLength: 1024, StagedPath: filepath.Join(root, "pb"),
		HostdAPIMin: 1, HostdAPIMax: 1, RuntimeAPIMin: 1, RuntimeAPIMax: 1,
		WorkerID: "runtime-2026.08.27.55", WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: time.Now().Add(-time.Minute).UTC(), HealthDeadline: time.Now().Add(time.Minute).UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	active, err := resolveUpdatedActive(context.Background(), path, version, func(context.Context, string) (workerupdate.Release, error) {
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != version || active.Platform != runtime.GOOS || active.Architecture != runtime.GOARCH {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}

func TestResolveUpdatedActiveDoesNotBypassSignedRevocation(t *testing.T) {
	called := false
	_, err := resolveUpdatedActive(context.Background(), filepath.Join(t.TempDir(), "transaction.json"), "2026.08.27.55", func(context.Context, string) (workerupdate.Release, error) {
		called = true
		return workerupdate.Release{}, workerupdate.ErrReleaseRevoked
	})
	if !called || !errors.Is(err, workerupdate.ErrReleaseRevoked) {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestResolveUpdatedActiveUsesPersistedPreviousReleaseForRollback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-current", Stage: updateflow.StageMonitoring,
		ActiveVersion: "2026.08.27.55", ActiveDigest: strings.Repeat("a", 64), ActiveLength: 900,
		ActiveHostdAPIMin: 1, ActiveHostdAPIMax: 1, ActiveRuntimeAPIMin: 1, ActiveRuntimeAPIMax: 1,
		CandidateVersion: "2026.08.27.56", CandidateDigest: strings.Repeat("b", 64), CandidateLength: 1024,
		StagedPath: filepath.Join(root, "pb"), HostdAPIMin: 1, HostdAPIMax: 1, RuntimeAPIMin: 1, RuntimeAPIMax: 1,
		WorkerID: "runtime-2026.08.27.56", WorkerEpoch: 2, BootID: "hostd",
		StageUpdatedAt: time.Now().Add(-time.Minute).UTC(), HealthDeadline: time.Now().Add(time.Minute).UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	var checked []string
	active, err := resolveUpdatedActive(context.Background(), path, journal.CandidateVersion, func(_ context.Context, version string) (workerupdate.Release, error) {
		checked = append(checked, version)
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != journal.ActiveVersion || strings.Join(checked, ",") != journal.CandidateVersion+","+journal.ActiveVersion {
		t.Fatalf("active=%+v checked=%v err=%v", active, checked, err)
	}
}

func TestResolveUpdatedActiveAfterCurrentIndexAdvancesWithoutTransaction(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "transaction.json")
	version := "2026.08.27.57"
	journal := updateflow.Journal{
		Schema: updateflow.SchemaV1, TransactionID: "txn-seed", Stage: updateflow.StageIdle,
		ActiveVersion: version, ActiveDigest: strings.Repeat("a", 64), ActiveLength: 900,
		ActiveHostdAPIMin: 1, ActiveHostdAPIMax: 1, ActiveRuntimeAPIMin: 1, ActiveRuntimeAPIMax: 1,
		BootID: "hostd", StageUpdatedAt: time.Now().UTC(),
	}
	if err := updateflow.Write(path, journal, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	active, err := resolveUpdatedActive(context.Background(), path, version, func(context.Context, string) (workerupdate.Release, error) {
		return workerupdate.Release{}, workerupdate.ErrInvalidRelease
	})
	if err != nil || active.Version != version || active.SHA256 != journal.ActiveDigest {
		t.Fatalf("active=%+v err=%v", active, err)
	}
}

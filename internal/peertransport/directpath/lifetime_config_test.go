package directpath

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type zeroLifetimeRandom struct{}

func (zeroLifetimeRandom) Uint64() (uint64, error) { return 0, nil }

func TestLifetimeConfigAppliesEvidenceOnlyToNewSession(t *testing.T) {
	policy := networkadaptation.DevelopmentLifetimePolicy()
	policy.JitterFraction = 0
	cache, err := networkadaptation.NewLifetimeCache(policy, zeroLifetimeRandom{})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := networkadaptation.Fingerprint{1}
	now := time.Unix(1000, 0)
	for index := range 3 {
		if err := cache.RecordSuccess(fingerprint, 30*time.Second, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	configured, err := applyLifetimeConfig(base, &LifetimeConfig{Cache: cache, Fingerprint: fingerprint, Now: func() time.Time { return now.Add(3 * time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	want := 30*time.Second/3 - policy.SafetyMargin
	if configured.KeepAlivePeriod != want || base.KeepAlivePeriod != policy.DefaultInterval {
		t.Fatalf("configured=%v base=%v want=%v", configured.KeepAlivePeriod, base.KeepAlivePeriod, want)
	}
}

func TestLifetimeConfigIsOptionalButNotPartial(t *testing.T) {
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	unchanged, err := applyLifetimeConfig(base, nil)
	if err != nil || unchanged != base {
		t.Fatalf("unchanged=%+v error=%v", unchanged, err)
	}
	if _, err := applyLifetimeConfig(base, &LifetimeConfig{}); err == nil {
		t.Fatal("partial lifetime configuration accepted")
	}
}

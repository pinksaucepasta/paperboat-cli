package connectionmanager

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

func TestQualityKeyAuthorityResolvesProbeAndActiveHealthBindings(t *testing.T) {
	key := qualityKey(11)
	authority, err := NewQualityKeyAuthority(key, 7)
	if err != nil {
		t.Fatal(err)
	}
	probeKey, err := authority.QualityKey(ProbeAttempt{Generation: 3, NetworkGeneration: 7})
	if err != nil || probeKey != key {
		t.Fatalf("probe key=%+v error=%v", probeKey, err)
	}
	activeKey, err := authority.ActiveHealthQualityKey(ActiveHealthBinding{Path: PathRelayQUIC, Generation: 4, NetworkGeneration: 7})
	if err != nil || activeKey != key {
		t.Fatalf("active key=%+v error=%v", activeKey, err)
	}
	if _, err := authority.QualityKey(ProbeAttempt{Generation: 3, NetworkGeneration: 6}); err == nil {
		t.Fatal("resolved stale probe network generation")
	}
	if _, err := authority.ActiveHealthQualityKey(ActiveHealthBinding{Path: PathDirectQUIC, Generation: 4, NetworkGeneration: 8}); err == nil {
		t.Fatal("resolved future active-health network generation")
	}
}

func TestQualityKeyAuthorityFencesActiveHealthRecordingAcrossNetworkChange(t *testing.T) {
	policy := DevelopmentQualityPolicy()
	cache, _ := NewQualityCache(policy)
	authority, _ := NewQualityKeyAuthority(qualityKey(41), 3)
	recorder, err := NewQualityActiveHealthRecorder(cache, authority)
	if err != nil {
		t.Fatal(err)
	}
	sample := ActiveHealthSample{
		Binding:  ActiveHealthBinding{Path: PathDirectQUIC, Generation: 2, NetworkGeneration: 3},
		Sequence: 1, At: time.Now().UTC(), Completed: time.Millisecond, Succeeded: true,
	}
	if err := recorder.RecordActiveHealth(sample); err != nil {
		t.Fatal(err)
	}
	authority.InvalidateNetwork(4)
	sample.Sequence++
	sample.At = sample.At.Add(policy.MinimumSampleInterval)
	if err := recorder.RecordActiveHealth(sample); err == nil {
		t.Fatal("recorded active health against invalidated network key")
	}
	next := qualityKey(42)
	if err := authority.Replace(next, 4); err != nil {
		t.Fatal(err)
	}
	sample.Binding.NetworkGeneration = 4
	sample.At = sample.At.Add(policy.MinimumSampleInterval)
	if err := recorder.RecordActiveHealth(sample); err != nil {
		t.Fatal(err)
	}
}

func TestQualityKeyAuthorityRejectsIdentityGenerationAndFingerprintRollback(t *testing.T) {
	initial := qualityKey(21)
	authority, _ := NewQualityKeyAuthority(initial, 5)
	changed := initial
	changed.MachineID = "machine_02"
	if err := authority.Replace(changed, 6); err == nil {
		t.Fatal("accepted machine identity substitution")
	}
	changed = initial
	changed.AuthorizationGeneration--
	if err := authority.Replace(changed, 6); err == nil {
		t.Fatal("accepted authorization rollback")
	}
	changed = initial
	changed.NetworkFingerprint[0]++
	if err := authority.Replace(changed, 5); err == nil {
		t.Fatal("accepted same-generation fingerprint substitution")
	}
	changed.AuthorizationGeneration++
	if err := authority.Replace(changed, 6); err != nil {
		t.Fatal(err)
	}
	if got, err := authority.QualityKey(ProbeAttempt{Generation: 1, NetworkGeneration: 6}); err != nil || got != changed {
		t.Fatalf("replacement=%+v error=%v", got, err)
	}
}

func TestQualityKeyAuthorityMaximumGenerationInvalidationIsTerminal(t *testing.T) {
	initial := qualityKey(24)
	authority, err := NewQualityKeyAuthority(initial, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	if invalidated := authority.Invalidate(); invalidated != 1 || !authority.exhausted {
		t.Fatalf("invalidated=%d exhausted=%t", invalidated, authority.exhausted)
	}
	replacement := initial
	replacement.NetworkFingerprint[0]++
	for range 2 {
		if replaceErr := authority.Replace(replacement, math.MaxUint64); !errors.Is(replaceErr, ErrQualityGenerationExhausted) {
			t.Fatalf("replace error=%v", replaceErr)
		}
		if authority.InvalidateNetwork(math.MaxUint64) != 0 || authority.ApplyNetworkEvent(networkmonitor.Event{Generation: math.MaxUint64, Rebind: true, Fingerprint: replacement.NetworkFingerprint, FingerprintValid: true}) != 0 {
			t.Fatal("exhausted authority accepted same-generation evidence")
		}
		if _, resolveErr := authority.QualityKey(ProbeAttempt{Generation: 1, NetworkGeneration: math.MaxUint64}); resolveErr == nil {
			t.Fatal("exhausted authority resolved a quality key")
		}
	}
}

func TestNetworkCoordinatorInvalidatesQualityKeyAuthority(t *testing.T) {
	recorder := &recoveryRecorder{}
	authority, _ := NewQualityKeyAuthority(qualityKey(31), 1)
	coordinator, err := NewNetworkCoordinator(&recordingQuality{recorder}, &recordingPool{recorder}, &recordingProbes{recorder}, authority)
	if err != nil {
		t.Fatal(err)
	}
	var fingerprint [32]byte
	fingerprint[0] = 99
	if !coordinator.Handle(networkmonitor.Event{Generation: 9, Rebind: true, Fingerprint: fingerprint, FingerprintValid: true}) {
		t.Fatal("network transition was not applied")
	}
	if _, err := authority.QualityKey(ProbeAttempt{Generation: 1, NetworkGeneration: 1}); err == nil {
		t.Fatal("old quality key survived coordinator invalidation")
	}
	automatic, err := authority.ActiveHealthQualityKey(ActiveHealthBinding{Path: PathWSS, Generation: 2, NetworkGeneration: 9})
	if err != nil || automatic.NetworkFingerprint != fingerprint {
		t.Fatalf("automatic replacement=%+v error=%v", automatic, err)
	}
	next := automatic
	next.AuthorizationGeneration++
	if err := authority.Replace(next, 2); err == nil {
		t.Fatal("accepted replacement older than coordinator generation")
	}
	if err := authority.Replace(next, 9); err != nil {
		t.Fatal(err)
	}
	if got, err := authority.ActiveHealthQualityKey(ActiveHealthBinding{Path: PathWSS, Generation: 2, NetworkGeneration: 9}); err != nil || got != next {
		t.Fatalf("replacement=%+v error=%v", got, err)
	}
}

func TestNetworkCoordinatorLeavesQualityKeyFencedWithoutFingerprint(t *testing.T) {
	recorder := &recoveryRecorder{}
	authority, _ := NewQualityKeyAuthority(qualityKey(33), 1)
	coordinator, _ := NewNetworkCoordinator(&recordingQuality{recorder}, &recordingPool{recorder}, &recordingProbes{recorder}, authority)
	if !coordinator.Handle(networkmonitor.Event{Generation: 2, Rebind: true}) {
		t.Fatal("network transition was not applied")
	}
	if _, err := authority.QualityKey(ProbeAttempt{Generation: 1, NetworkGeneration: 2}); err == nil {
		t.Fatal("quality key resumed without an opaque fingerprint")
	}
}

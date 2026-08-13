package connectionmanager

import (
	"encoding/binary"
	"math"
	"sort"
	"testing"
	"time"
)

func FuzzQualityCacheMatchesReferenceModel(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 0, 10, 0, 1, 1, 5, 2, 0, 20, 0, 0})
	f.Add([]byte{1, 4, 3, 0xff, 0xff, 1, 1, 4, 3, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		policy := DevelopmentQualityPolicy()
		policy.MaximumSamples = 16
		cache, err := NewQualityCache(policy)
		if err != nil {
			t.Fatal(err)
		}
		key := qualityKey(42)
		base := time.Unix(10_000, 0)
		accepted := map[Path][]QualityObservation{PathDirectQUIC: {}, PathRelayQUIC: {}}

		for offset := 0; offset+4 < len(data) && offset < 5*128; offset += 5 {
			path := PathDirectQUIC
			if data[offset]&1 != 0 {
				path = PathRelayQUIC
			}
			seconds := int8(data[offset+1])
			observation := QualityObservation{
				Path:       path,
				At:         base.Add(time.Duration(seconds) * time.Second),
				Completion: time.Duration(uint32(binary.BigEndian.Uint16(data[offset+2:offset+4]))+1) * time.Microsecond,
				Succeeded:  data[offset+4]&1 != 0,
				PTOs:       uint32(data[offset+4] >> 1),
			}
			duplicate := observationAt(accepted[path], observation.At)
			err := cache.Record(key, observation)
			if duplicate {
				if err == nil {
					t.Fatal("duplicate timestamp accepted")
				}
				continue
			}
			if err != nil {
				t.Fatalf("record: %v", err)
			}
			accepted[path] = append(accepted[path], observation)
			sort.Slice(accepted[path], func(i, j int) bool { return accepted[path][i].At.Before(accepted[path][j].At) })
			if excess := len(accepted[path]) - policy.MaximumSamples; excess > 0 {
				accepted[path] = append([]QualityObservation(nil), accepted[path][excess:]...)
			}
		}

		now := base.Add(time.Duration(int8(byteAt(data, len(data)-1))) * time.Second)
		_, direct, relay, err := cache.Select(key, now)
		if err != nil {
			t.Fatal(err)
		}
		assertQualitySnapshot(t, direct, referenceQualitySnapshot(policy, PathDirectQUIC, accepted[PathDirectQUIC], now))
		assertQualitySnapshot(t, relay, referenceQualitySnapshot(policy, PathRelayQUIC, accepted[PathRelayQUIC], now))
		if len(cache.items[key].direct) > policy.MaximumSamples || len(cache.items[key].relay) > policy.MaximumSamples {
			t.Fatalf("stored samples exceed bound: direct=%d relay=%d", len(cache.items[key].direct), len(cache.items[key].relay))
		}
	})
}

func referenceQualitySnapshot(policy QualityPolicy, path Path, observations []QualityObservation, now time.Time) QualitySnapshot {
	retentionStart := now.Add(-policy.SampleRetention)
	retained := make([]QualityObservation, 0, len(observations))
	for _, observation := range observations {
		if !observation.At.Before(retentionStart) {
			retained = append(retained, observation)
		}
	}
	result := QualitySnapshot{Path: path}
	lossStart := now.Add(-policy.LossWindow)
	lossTotal, lossFailures := 0, 0
	independent := make([]QualityObservation, 0, len(retained))
	for _, observation := range retained {
		if !observation.At.Before(lossStart) && !observation.At.After(now) {
			lossTotal++
			result.PTOs += observation.PTOs
			if !observation.Succeeded {
				lossFailures++
			}
		}
		if observation.Succeeded && !observation.At.After(now) &&
			(len(independent) == 0 || observation.At.Sub(independent[len(independent)-1].At) >= policy.MinimumSampleInterval) {
			independent = append(independent, observation)
		}
	}
	if lossTotal > 0 {
		result.LossPercent = float64(lossFailures) * 100 / float64(lossTotal)
	}
	result.Suspect = result.LossPercent > policy.SuspectLossPercent || result.PTOs >= policy.SuspectPTOs
	result.Samples = len(independent)
	if len(independent) > 1 {
		result.Span = independent[len(independent)-1].At.Sub(independent[0].At)
	}
	if result.Samples < policy.MinimumSamples || result.Span < policy.MinimumSampleSpan {
		return result
	}
	durations := make([]time.Duration, len(independent))
	for index := range independent {
		durations[index] = independent[index].Completion
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	result.P95 = durations[(95*len(durations)+99)/100-1]
	result.Qualified = true
	return result
}

func assertQualitySnapshot(t *testing.T, got, want QualitySnapshot) {
	t.Helper()
	if got.Path != want.Path || got.P95 != want.P95 || got.Samples != want.Samples || got.Span != want.Span ||
		math.Float64bits(got.LossPercent) != math.Float64bits(want.LossPercent) || got.PTOs != want.PTOs ||
		got.Suspect != want.Suspect || got.Qualified != want.Qualified {
		t.Fatalf("snapshot=%+v want=%+v", got, want)
	}
}

func observationAt(observations []QualityObservation, at time.Time) bool {
	for _, observation := range observations {
		if observation.At.Equal(at) {
			return true
		}
	}
	return false
}

func byteAt(data []byte, index int) byte {
	if index < 0 || index >= len(data) {
		return 0
	}
	return data[index]
}

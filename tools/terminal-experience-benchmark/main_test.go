//go:build darwin || linux

package main

import (
	"testing"
	"time"
)

func TestSummarizeOutputCadence(t *testing.T) {
	base := time.Unix(0, 0)
	events := []readEvent{
		{at: base, n: 10},
		{at: base.Add(10 * time.Millisecond), n: 20},
		{at: base.Add(30 * time.Millisecond), n: 30},
		{at: base.Add(130 * time.Millisecond), n: 40},
	}
	got := summarize("quic", 2, time.Second, events)
	if got.Bytes != 100 || got.Events != 4 || got.BytesSec != 100 {
		t.Fatalf("volume summary = %+v", got)
	}
	if got.GapP50MS != 20 || got.GapP95MS != 100 || got.GapP99MS != 100 || got.MaxGapMS != 100 {
		t.Fatalf("gap summary = %+v", got)
	}
	if got.Over16MS != 2 || got.Over33MS != 1 || got.Over50MS != 1 || got.Over100MS != 0 {
		t.Fatalf("threshold summary = %+v", got)
	}
}

func TestSummarizeHandlesSparseOutput(t *testing.T) {
	got := summarize("ssh", 1, time.Second, []readEvent{{at: time.Now(), n: 7}})
	if got.Bytes != 7 || got.Events != 1 || got.MaxGapMS != 0 {
		t.Fatalf("summary = %+v", got)
	}
}

func TestPercentileUsesNearestRank(t *testing.T) {
	values := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond}
	if got := percentile(values, 50); got != 3*time.Millisecond {
		t.Fatalf("p50 = %v", got)
	}
	if got := percentile(values, 99); got != 5*time.Millisecond {
		t.Fatalf("p99 = %v", got)
	}
}

func TestSummarizeRuns(t *testing.T) {
	got := summarizeRuns("pb_quic", []sample{
		{BytesSec: 100, GapP95MS: 20, GapP99MS: 30, MaxGapMS: 80, Over33MS: 2, Over50MS: 1},
		{BytesSec: 140, GapP95MS: 22, GapP99MS: 35, MaxGapMS: 120, Over33MS: 3, Over50MS: 2, Over100MS: 1},
	})
	if got.Runs != 2 || got.MeanBytesSec != 120 || got.MedianP95MS != 20 || got.MedianP99MS != 30 || got.MedianMaxMS != 80 || got.WorstGapMS != 120 {
		t.Fatalf("aggregate = %+v", got)
	}
	if got.TotalOver33MS != 5 || got.TotalOver50MS != 3 || got.TotalOver100MS != 1 {
		t.Fatalf("aggregate thresholds = %+v", got)
	}
}

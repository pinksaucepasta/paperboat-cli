//go:build darwin || linux

package main

import (
	"testing"
	"time"
)

func TestSummaries(t *testing.T) {
	values := []time.Duration{100 * time.Millisecond, 150 * time.Millisecond, 250 * time.Millisecond, 600 * time.Millisecond}
	value := summarize("pb_quic", 1, values)
	if value.P50MS != 150 || value.P95MS != 600 || value.MaxMS != 600 || value.Over200MS != 2 || value.Over500MS != 1 {
		t.Fatalf("result = %+v", value)
	}
	aggregate := summarizeRuns("pb_quic", []result{value, result{Samples: 4, P50MS: 120, P95MS: 300, P99MS: 400, MaxMS: 450, Over200MS: 1}})
	if aggregate.Samples != 8 || aggregate.MedianP50MS != 120 || aggregate.MedianP95MS != 300 || aggregate.MedianMaxMS != 450 || aggregate.WorstMS != 600 || aggregate.TotalOver200MS != 3 {
		t.Fatalf("aggregate = %+v", aggregate)
	}
}

func TestMedian(t *testing.T) {
	if got := median([]float64{3, 1, 2}); got != 2 {
		t.Fatalf("median = %v", got)
	}
}

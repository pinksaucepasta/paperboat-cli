package diagnosticlog

import (
	"testing"
	"time"
)

func TestTryInfoNeverWaitsForBackend(t *testing.T) {
	started := time.Now()
	for range queueDepth * 4 {
		TryInfo("diagnostic test")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("nonblocking logging took %s", elapsed)
	}
}

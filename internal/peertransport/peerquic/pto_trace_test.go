package peerquic

import (
	"testing"

	"github.com/quic-go/quic-go/qlog"
)

func TestPTOTraceCountsExpirationsAcrossResets(t *testing.T) {
	trace := newPTOTrace()
	recorder := trace.AddProducer()
	for _, count := range []uint32{1, 2, 0, 1, 0} {
		recorder.RecordEvent(qlog.PTOCountUpdated{PTOCount: count})
	}
	if got := trace.total.Load(); got != 3 {
		t.Fatalf("PTO total=%d want 3", got)
	}
	if got := trace.current.Load(); got != 0 {
		t.Fatalf("current PTO count=%d", got)
	}
	select {
	case <-trace.changed:
	default:
		t.Fatal("PTO progress did not notify observers")
	}
	if !trace.SupportsSchemas(qlog.EventSchema) || trace.SupportsSchemas("other") {
		t.Fatal("unexpected qlog schema support")
	}
}

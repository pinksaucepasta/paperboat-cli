package networkadaptation

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

func TestLifetimeDecisionConfiguresOnlyNewQUICSession(t *testing.T) {
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	adapted, err := ApplyLifetimeDecision(base, LifetimeDecision{Interval: 20 * time.Second, LowerBound: time.Minute, Evidence: 3, Adapted: true})
	if err != nil {
		t.Fatal(err)
	}
	if adapted.KeepAlivePeriod != 20*time.Second || base.KeepAlivePeriod != 3*time.Second {
		t.Fatalf("adapted=%+v base=%+v", adapted, base)
	}
}

func TestLifetimeDecisionCannotExceedSessionIdleSafety(t *testing.T) {
	base := peerquic.DevelopmentSessionConfig(peerquic.ClassInteractive)
	if _, err := ApplyLifetimeDecision(base, LifetimeDecision{Interval: time.Minute}); err == nil {
		t.Fatal("unsafe keepalive accepted")
	}
	if _, err := ApplyLifetimeDecision(base, LifetimeDecision{}); err == nil {
		t.Fatal("empty decision accepted")
	}
}

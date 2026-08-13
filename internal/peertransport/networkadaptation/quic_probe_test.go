package networkadaptation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type fakeQUICProbeDialer struct {
	session *fakeQUICProbeSession
	err     error
	idle    time.Duration
}

func (d *fakeQUICProbeDialer) DialLifetimeProbe(_ context.Context, idle time.Duration) (QUICProbeSession, error) {
	d.idle = idle
	return d.session, d.err
}

type fakeQUICProbeSession struct {
	at         time.Time
	probeErr   error
	closeErr   error
	probeCalls atomic.Int32
	closes     atomic.Int32
}

func (s *fakeQUICProbeSession) ProbeAfterIdle(context.Context, time.Duration) (time.Time, error) {
	s.probeCalls.Add(1)
	return s.at, s.probeErr
}
func (s *fakeQUICProbeSession) Close() error { s.closes.Add(1); return s.closeErr }

func TestQUICLifetimeProberReturnsAuthenticatedReachability(t *testing.T) {
	at := time.Unix(50_000, 0)
	session := &fakeQUICProbeSession{at: at}
	dialer := &fakeQUICProbeDialer{session: session}
	prober, err := NewQUICLifetimeProber(dialer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.ProbeAfterIdle(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reachable || result.At != at || dialer.idle != time.Minute || session.closes.Load() != 1 {
		t.Fatalf("result=%+v idle=%v closes=%d", result, dialer.idle, session.closes.Load())
	}
}

func TestQUICLifetimeProberClassifiesOnlyPostIdleDeadlineAsUnreachable(t *testing.T) {
	session := &fakeQUICProbeSession{probeErr: peerquic.ErrLifetimeProbeUnreachable}
	prober, _ := NewQUICLifetimeProber(&fakeQUICProbeDialer{session: session})
	result, err := prober.ProbeAfterIdle(context.Background(), time.Second)
	if err != nil || result.Reachable || result.At.IsZero() {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	for name, want := range map[string]error{
		"certificate": errors.New("certificate mismatch"),
		"protocol":    errors.New("nonce mismatch"),
		"canceled":    context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			session := &fakeQUICProbeSession{probeErr: want}
			prober, _ := NewQUICLifetimeProber(&fakeQUICProbeDialer{session: session})
			if _, err := prober.ProbeAfterIdle(context.Background(), time.Second); !errors.Is(err, want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestQUICLifetimeProberFailsClosedOnDialOrCleanup(t *testing.T) {
	wantDial := errors.New("ICE failed")
	prober, _ := NewQUICLifetimeProber(&fakeQUICProbeDialer{err: wantDial})
	if _, err := prober.ProbeAfterIdle(context.Background(), time.Second); !errors.Is(err, wantDial) {
		t.Fatalf("dial error = %v", err)
	}
	wantClose := errors.New("session cleanup failed")
	session := &fakeQUICProbeSession{at: time.Now(), closeErr: wantClose}
	prober, _ = NewQUICLifetimeProber(&fakeQUICProbeDialer{session: session})
	if _, err := prober.ProbeAfterIdle(context.Background(), time.Second); !errors.Is(err, wantClose) {
		t.Fatalf("close error = %v", err)
	}
}

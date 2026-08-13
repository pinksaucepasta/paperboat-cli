package networkadaptation

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type QUICProbeSession interface {
	ProbeAfterIdle(context.Context, time.Duration) (time.Time, error)
	Close() error
}

// QUICProbeDialer must complete ICE nomination and endpoint-authenticated
// probe-only QUIC before returning. The idle argument lets it configure a
// QUIC idle horizon that cannot expire before the requested observation.
type QUICProbeDialer interface {
	DialLifetimeProbe(context.Context, time.Duration) (QUICProbeSession, error)
}

type QUICLifetimeProber struct {
	dialer QUICProbeDialer
}

func NewQUICLifetimeProber(dialer QUICProbeDialer) (*QUICLifetimeProber, error) {
	if dialer == nil {
		return nil, ErrInvalid
	}
	return &QUICLifetimeProber{dialer: dialer}, nil
}

func (p *QUICLifetimeProber) ProbeAfterIdle(ctx context.Context, idle time.Duration) (ProbeResult, error) {
	if p == nil || p.dialer == nil || ctx == nil || idle <= 0 {
		return ProbeResult{}, ErrInvalid
	}
	session, err := p.dialer.DialLifetimeProbe(ctx, idle)
	if err != nil {
		return ProbeResult{}, err
	}
	if nilQUICProbeSession(session) {
		return ProbeResult{}, ErrInvalid
	}
	at, probeErr := session.ProbeAfterIdle(ctx, idle)
	closeErr := session.Close()
	if closeErr != nil {
		return ProbeResult{}, closeErr
	}
	if probeErr != nil {
		if err := ctx.Err(); err != nil {
			return ProbeResult{}, err
		}
		if errors.Is(probeErr, peerquic.ErrLifetimeProbeUnreachable) {
			return ProbeResult{At: time.Now().UTC()}, nil
		}
		return ProbeResult{}, probeErr
	}
	if at.IsZero() {
		return ProbeResult{}, ErrInvalid
	}
	return ProbeResult{Reachable: true, At: at}, nil
}

func nilQUICProbeSession(session QUICProbeSession) bool {
	if session == nil {
		return true
	}
	value := reflect.ValueOf(session)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

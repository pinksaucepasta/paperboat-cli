package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type selectorPrepared struct {
	attached *atomic.Int32
	closed   *atomic.Int32
}

func (p *selectorPrepared) Attach(context.Context) (Conn, error) {
	p.attached.Add(1)
	return selectorConn{}, nil
}
func (p *selectorPrepared) Close() error { p.closed.Add(1); return nil }

type selectorConn struct{}

func (selectorConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (selectorConn) Write(p []byte) (int, error) { return len(p), nil }
func (selectorConn) Close() error                { return nil }
func (selectorConn) Resize(uint16, uint16) error { return nil }
func (selectorConn) Wait() (int, error)          { return 0, nil }

type selectorEstablisher struct {
	delay                     time.Duration
	err                       error
	ignoreCancellation        bool
	started, attached, closed *atomic.Int32
}

func (s *selectorEstablisher) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	p, err := s.Establish(ctx, info)
	if err != nil {
		return nil, err
	}
	return p.Attach(ctx)
}
func (s *selectorEstablisher) Establish(ctx context.Context, _ resolver.ConnectInfo) (preparedTerminal, error) {
	s.started.Add(1)
	timer := time.NewTimer(s.delay)
	defer timer.Stop()
	canceled := ctx.Done()
	if s.ignoreCancellation {
		canceled = nil
	}
	select {
	case <-timer.C:
	case <-canceled:
		return nil, ctx.Err()
	}
	if s.err != nil {
		return nil, s.err
	}
	return &selectorPrepared{attached: s.attached, closed: s.closed}, nil
}

func TestAutoRacesEstablishmentAndAttachesOnlyWinner(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{delay: 300 * time.Millisecond, ignoreCancellation: true, started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{delay: 5 * time.Millisecond, started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	conn, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://example.test:443"}})
	if err != nil || conn == nil {
		t.Fatal(err)
	}
	if qs.Load() != 1 || ws.Load() != 1 || qa.Load() != 0 || wa.Load() != 1 {
		t.Fatalf("starts=%d/%d attaches=%d/%d", qs.Load(), ws.Load(), qa.Load(), wa.Load())
	}
}

func TestAutoDoesNotFallbackOnAuthoritativeFailure(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{err: errors.New("certificate rejected"), started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	if _, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://example.test:443"}}); err == nil {
		t.Fatal("expected failure")
	}
	if ws.Load() != 0 {
		t.Fatalf("WSS started after authoritative failure: %d", ws.Load())
	}
}

func TestAutoFallsBackOnTransportFailure(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{err: &terminalTransportError{transport: "QUIC", cause: errors.New("UDP unavailable")}, started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	if _, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://example.test:443"}}); err != nil {
		t.Fatal(err)
	}
	if ws.Load() != 1 || wa.Load() != 1 {
		t.Fatalf("WSS starts=%d attaches=%d", ws.Load(), wa.Load())
	}
	if qc.Load() != 0 || wc.Load() != 0 {
		t.Fatalf("completed candidates unexpectedly closed: quic=%d wss=%d", qc.Load(), wc.Load())
	}
}

func TestAutoRecoversFromStickyWSSFailureWithQUIC(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{err: &terminalTransportError{transport: "WSS", cause: errors.New("TCP unavailable")}, started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	host := "example.test"
	selector.markWSSSticky(host)
	conn, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://" + host + ":443"}})
	if err != nil || conn == nil {
		t.Fatal(err)
	}
	if ws.Load() != 1 || qs.Load() != 1 || wa.Load() != 0 || qa.Load() != 1 {
		t.Fatalf("starts=%d/%d attaches=%d/%d", ws.Load(), qs.Load(), wa.Load(), qa.Load())
	}
	if selector.isWSSSticky(host) {
		t.Fatal("successful QUIC recovery did not clear sticky WSS preference")
	}
}

func TestAutoClosesPendingPreparedLoser(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{delay: 300 * time.Millisecond, ignoreCancellation: true, started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{delay: 5 * time.Millisecond, started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	if _, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://example.test:443"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for qc.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("pending QUIC candidate was not closed")
		}
		time.Sleep(time.Millisecond)
	}
	if wc.Load() != 0 || qa.Load() != 0 || wa.Load() != 1 {
		t.Fatalf("closed=%d/%d attached=%d/%d", qc.Load(), wc.Load(), qa.Load(), wa.Load())
	}
}

func TestAutoPersistsQUICWinner(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	quic := &selectorEstablisher{started: &qs, attached: &qa, closed: &qc}
	wss := &selectorEstablisher{delay: time.Second, started: &ws, attached: &wa, closed: &wc}
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, quic, wss)
	path := filepath.Join(t.TempDir(), "terminal-transport.json")
	if err := selector.SetPreferencePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Dial(context.Background(), resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{QUICEndpoint: "quic://example.test:443"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]terminalTransportPreference
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	preference := persisted["example.test"]
	if preference.Transport != TerminalTransportDirect || !preference.ExpiresAt.After(time.Now()) {
		t.Fatalf("preference = %#v", preference)
	}
}

func TestExpiredTransportPreferenceIsDiscarded(t *testing.T) {
	var qs, qa, qc, ws, wa, wc atomic.Int32
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto,
		&selectorEstablisher{started: &qs, attached: &qa, closed: &qc},
		&selectorEstablisher{started: &ws, attached: &wa, closed: &wc})
	selector.preferences["example.test"] = terminalTransportPreference{Transport: TerminalTransportRelayWSS, ExpiresAt: time.Now().Add(-time.Second)}
	if _, ok := selector.preferred("example.test"); ok {
		t.Fatal("expired preference was retained")
	}
}

func TestTransportPreferencePersistenceFailureIsRetained(t *testing.T) {
	selector, _ := NewTerminalTransportSelector(TerminalTransportAuto, &selectorEstablisher{}, &selectorEstablisher{})
	root := t.TempDir()
	directory := filepath.Join(root, "blocked")
	path := filepath.Join(directory, "preference.json")
	if err := selector.SetPreferencePath(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	selector.markPreferred("example.test", TerminalTransportDirect)
	if selector.PreferenceError() == nil {
		t.Fatal("preference persistence failure was discarded")
	}
}

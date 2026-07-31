package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type TerminalTransport string

const (
	TerminalTransportAuto TerminalTransport = "auto"
	TerminalTransportQUIC TerminalTransport = "quic"
	TerminalTransportWSS  TerminalTransport = "wss"
)

func ParseTerminalTransport(value string) (TerminalTransport, error) {
	mode := TerminalTransport(strings.ToLower(strings.TrimSpace(value)))
	switch mode {
	case TerminalTransportAuto, TerminalTransportQUIC, TerminalTransportWSS:
		return mode, nil
	default:
		return "", errors.New("terminal transport must be auto, quic, or wss")
	}
}

type TerminalTransportSelector struct {
	Mode     TerminalTransport
	QUIC     Tunnel
	WSS      Tunnel
	Observer func(TerminalTransportSelection, string)

	mu             sync.Mutex
	preferences    map[string]terminalTransportPreference
	now            func() time.Time
	preferencePath string
}

type terminalTransportPreference struct {
	Transport TerminalTransport `json:"transport"`
	ExpiresAt time.Time         `json:"expires_at"`
}

func (s *TerminalTransportSelector) SetPreferencePath(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preferencePath = path
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var persisted map[string]terminalTransportPreference
	if json.Unmarshal(data, &persisted) != nil {
		return nil
	}
	for host, preference := range persisted {
		if host != "" && (preference.Transport == TerminalTransportQUIC || preference.Transport == TerminalTransportWSS) && s.now().Before(preference.ExpiresAt) {
			s.preferences[host] = preference
		}
	}
	return nil
}

type terminalChecker interface {
	Check(context.Context, *resolver.TerminalTarget) error
}

type preparedTerminal interface {
	Attach(context.Context) (Conn, error)
	Close() error
}

type terminalEstablisher interface {
	Establish(context.Context, resolver.ConnectInfo) (preparedTerminal, error)
}

type TerminalTransportSelection struct {
	Requested TerminalTransport
	Selected  string
	Fallback  string
}

func NewTerminalTransportSelector(mode TerminalTransport, quic, wss Tunnel) (*TerminalTransportSelector, error) {
	if _, err := ParseTerminalTransport(string(mode)); err != nil || quic == nil || wss == nil {
		return nil, errors.New("invalid terminal transport selector")
	}
	return &TerminalTransportSelector{Mode: mode, QUIC: quic, WSS: wss, preferences: make(map[string]terminalTransportPreference), now: time.Now}, nil
}

func (s *TerminalTransportSelector) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	switch s.Mode {
	case TerminalTransportQUIC:
		connection, err := s.QUIC.Dial(ctx, info)
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "quic", Fallback: "none"}, err)
		return connection, err
	case TerminalTransportWSS:
		connection, err := s.WSS.Dial(ctx, info)
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "wss", Fallback: "none"}, err)
		return connection, err
	}
	if _, quicOK := s.QUIC.(terminalEstablisher); quicOK {
		if _, wssOK := s.WSS.(terminalEstablisher); wssOK {
			return s.dialAuto(ctx, info)
		}
	}
	host := terminalTargetHost(info.Terminal)
	if s.isWSSSticky(host) {
		connection, err := s.WSS.Dial(ctx, info)
		if err == nil || !FallbackEligible(err) {
			s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "wss", Fallback: "sticky_wss"}, err)
			return connection, err
		}
		connection, quicErr := s.QUIC.Dial(ctx, info)
		if quicErr != nil {
			combined := combineTransportFailures(err, quicErr)
			fallback := "wss_connect"
			if FallbackEligible(combined) {
				fallback = "both_unavailable"
			}
			s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "quic", Fallback: fallback}, combined)
			return nil, combined
		}
		s.clearWSSSticky(host)
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "quic", Fallback: "wss_connect"}, nil)
		return connection, nil
	}
	connection, err := s.QUIC.Dial(ctx, info)
	if err == nil {
		s.markPreferred(host, TerminalTransportQUIC)
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "quic", Fallback: "none"}, nil)
		return connection, nil
	}
	if !FallbackEligible(err) {
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "quic", Fallback: "none"}, err)
		return connection, err
	}
	connection, wssErr := s.WSS.Dial(ctx, info)
	if wssErr != nil {
		combined := combineTransportFailures(err, wssErr)
		fallback := "quic_connect"
		if FallbackEligible(combined) {
			fallback = "both_unavailable"
		}
		s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "wss", Fallback: fallback}, combined)
		return nil, combined
	}
	s.markPreferred(host, TerminalTransportWSS)
	s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: "wss", Fallback: "quic_connect"}, nil)
	return connection, nil
}

type establishResult struct {
	mode     TerminalTransport
	prepared preparedTerminal
	err      error
}

func (s *TerminalTransportSelector) dialAuto(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	host := terminalTargetHost(info.Terminal)
	first, second := TerminalTransportQUIC, TerminalTransportWSS
	if preferred, ok := s.preferred(host); ok && preferred == TerminalTransportWSS {
		first, second = second, first
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan establishResult, 2)
	start := func(mode TerminalTransport) {
		tunnel := s.QUIC
		if mode == TerminalTransportWSS {
			tunnel = s.WSS
		}
		go func() {
			prepared, err := tunnel.(terminalEstablisher).Establish(raceCtx, info)
			results <- establishResult{mode: mode, prepared: prepared, err: err}
		}()
	}
	start(first)
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	startedSecond := false
	var firstErr error
	attempts := 0
	cleanupPending := func() {
		pending := 1 - attempts
		if startedSecond {
			pending++
		}
		for range pending {
			go func() {
				other := <-results
				if other.prepared != nil {
					_ = other.prepared.Close()
				}
			}()
		}
	}
	for attempts < 2 {
		select {
		case <-timer.C:
			if !startedSecond {
				start(second)
				startedSecond = true
			}
		case result := <-results:
			attempts++
			if result.err == nil {
				cancel()
				cleanupPending()
				connection, err := result.prepared.Attach(ctx)
				if err != nil {
					_ = result.prepared.Close()
					s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: string(result.mode), Fallback: "none"}, err)
					return nil, err
				}
				s.markPreferred(host, result.mode)
				fallback := "none"
				if attempts > 1 || startedSecond && result.mode == second {
					fallback = string(first) + "_connect"
				}
				s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: string(result.mode), Fallback: fallback}, nil)
				return connection, nil
			}
			if !FallbackEligible(result.err) {
				cancel()
				cleanupPending()
				s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: string(result.mode), Fallback: "none"}, result.err)
				return nil, result.err
			}
			firstErr = errors.Join(firstErr, result.err)
			if !startedSecond {
				if timer.Stop() {
				}
				start(second)
				startedSecond = true
			}
		case <-ctx.Done():
			cancel()
			cleanupPending()
			return nil, ctx.Err()
		}
	}
	err := &terminalTransportError{transport: "QUIC and WSS", cause: firstErr}
	s.observe(TerminalTransportSelection{Requested: s.Mode, Selected: string(second), Fallback: "both_unavailable"}, err)
	return nil, err
}

func combineTransportFailures(first, second error) error {
	if !FallbackEligible(second) {
		return second
	}
	return &terminalTransportError{transport: "QUIC and WSS", cause: errors.Join(first, second)}
}

func (s *TerminalTransportSelector) observe(selection TerminalTransportSelection, err error) {
	if s.Observer == nil {
		return
	}
	outcome := "selected"
	if err != nil {
		outcome = "failure"
	}
	s.Observer(selection, outcome)
}

func (s *TerminalTransportSelector) Check(ctx context.Context, target *resolver.TerminalTarget) (TerminalTransportSelection, error) {
	selection := TerminalTransportSelection{Requested: s.Mode, Fallback: "none"}
	quicChecker, quicOK := s.QUIC.(terminalChecker)
	wssChecker, wssOK := s.WSS.(terminalChecker)
	if !quicOK || !wssOK {
		return selection, errors.New("terminal transport does not support diagnostics")
	}
	if s.Mode == TerminalTransportQUIC {
		selection.Selected = "quic"
		return selection, quicChecker.Check(ctx, target)
	}
	if s.Mode == TerminalTransportWSS {
		selection.Selected = "wss"
		return selection, wssChecker.Check(ctx, target)
	}
	host := terminalTargetHost(target)
	if s.isWSSSticky(host) {
		selection.Selected = "wss"
		selection.Fallback = "sticky_wss"
		err := wssChecker.Check(ctx, target)
		if err == nil || !FallbackEligible(err) {
			return selection, err
		}
		selection.Selected = "quic"
		selection.Fallback = "wss_connect"
		if quicErr := quicChecker.Check(ctx, target); quicErr != nil {
			combined := combineTransportFailures(err, quicErr)
			if FallbackEligible(combined) {
				selection.Fallback = "both_unavailable"
			}
			return selection, combined
		}
		s.clearWSSSticky(host)
		return selection, nil
	}
	selection.Selected = "quic"
	err := quicChecker.Check(ctx, target)
	if err == nil || !FallbackEligible(err) {
		return selection, err
	}
	selection.Selected = "wss"
	selection.Fallback = "quic_connect"
	if wssErr := wssChecker.Check(ctx, target); wssErr != nil {
		combined := combineTransportFailures(err, wssErr)
		if FallbackEligible(combined) {
			selection.Fallback = "both_unavailable"
		}
		return selection, combined
	}
	s.markPreferred(host, TerminalTransportWSS)
	return selection, nil
}

func (s *TerminalTransportSelector) isWSSSticky(host string) bool {
	preferred, ok := s.preferred(host)
	return ok && preferred == TerminalTransportWSS
}

func (s *TerminalTransportSelector) preferred(host string) (TerminalTransport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	preference, ok := s.preferences[host]
	if ok && !s.now().Before(preference.ExpiresAt) {
		delete(s.preferences, host)
		s.persistLocked()
		return "", false
	}
	return preference.Transport, ok
}

func (s *TerminalTransportSelector) markWSSSticky(host string) {
	s.markPreferred(host, TerminalTransportWSS)
}

func (s *TerminalTransportSelector) markPreferred(host string, transport TerminalTransport) {
	if host == "" {
		return
	}
	s.mu.Lock()
	s.preferences[host] = terminalTransportPreference{Transport: transport, ExpiresAt: s.now().Add(30 * time.Minute)}
	s.persistLocked()
	s.mu.Unlock()
}

func (s *TerminalTransportSelector) clearWSSSticky(host string) {
	s.markPreferred(host, TerminalTransportQUIC)
}

func (s *TerminalTransportSelector) persistLocked() {
	if s.preferencePath == "" {
		return
	}
	data, err := json.Marshal(s.preferences)
	if err != nil {
		return
	}
	dir := filepath.Dir(s.preferencePath)
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	temporary, err := os.CreateTemp(dir, "transport-preference-*")
	if err != nil {
		return
	}
	name := temporary.Name()
	defer os.Remove(name)
	if temporary.Chmod(0600) != nil {
		_ = temporary.Close()
		return
	}
	if _, err = temporary.Write(data); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		_ = os.Rename(name, s.preferencePath)
	}
}

func terminalTargetHost(target *resolver.TerminalTarget) string {
	if target == nil {
		return ""
	}
	parsed, err := url.Parse(target.QUICEndpoint)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

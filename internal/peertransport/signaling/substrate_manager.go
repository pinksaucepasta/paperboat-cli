package signaling

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"sync"
)

const maximumRegionalSubstrates = 16

// SubstrateManager retains the bounded daemon-wide set of discovered regional
// signaling connections. These are lightweight control paths, not peer or
// machine data carriers; attempt credentials remain independently authenticated.
type SubstrateManager struct {
	mu         sync.Mutex
	substrates map[string]*Substrate
	closed     bool
}

func (m *SubstrateManager) Warm(ctx context.Context, rawURL string, tlsConfig *tls.Config) error {
	started := time.Now()
	substrate, err := m.current(rawURL, tlsConfig)
	if err != nil {
		diagnosticlog.TryInfo("peer signaling substrate warm", "outcome", "invalid", "elapsed_ms", time.Since(started).Milliseconds())
		return err
	}
	err = substrate.Warm(ctx)
	host := "unknown"
	if parsed, parseErr := url.Parse(rawURL); parseErr == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	outcome := "ready"
	if err != nil {
		outcome = "failed"
	}
	diagnosticlog.TryInfo("peer signaling substrate warm", "host", host, "outcome", outcome, "elapsed_ms", time.Since(started).Milliseconds())
	return err
}

func (m *SubstrateManager) Open(ctx context.Context, config WebSocketConfig) (*SubstrateTransport, error) {
	if !validWebSocketCredential(config.Credential) {
		return nil, ErrTransportInvalid
	}
	substrate, err := m.current(config.URL, config.TLS)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	transport, err := substrate.Open(ctx, config.Credential)
	host := "unknown"
	if parsed, parseErr := url.Parse(config.URL); parseErr == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	diagnosticlog.TryInfo("peer signaling substrate open", "host", host, "outcome", map[bool]string{true: "ready", false: "failed"}[err == nil], "elapsed_ms", time.Since(started).Milliseconds())
	return transport, err
}

func (m *SubstrateManager) current(rawURL string, tlsConfig *tls.Config) (*Substrate, error) {
	canonical, err := canonicalSubstrateURL(rawURL)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errSubstrateClosed
	}
	if existing := m.substrates[canonical]; existing != nil {
		return existing, nil
	}
	if len(m.substrates) >= maximumRegionalSubstrates {
		return nil, ErrTransportUnavailable
	}
	replacement, err := NewSubstrate(WebSocketConfig{URL: canonical, TLS: tlsConfig})
	if err != nil {
		return nil, err
	}
	if m.substrates == nil {
		m.substrates = make(map[string]*Substrate)
	}
	m.substrates[canonical] = replacement
	return replacement, nil
}

func canonicalSubstrateURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrTransportInvalid
	}
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port == "" || port == "443" {
		parsed.Host = hostname
		if strings.Contains(hostname, ":") {
			parsed.Host = "[" + hostname + "]"
		}
	} else {
		parsed.Host = net.JoinHostPort(hostname, port)
	}
	parsed.Scheme = "wss"
	return parsed.String(), nil
}

func (m *SubstrateManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	substrates := m.substrates
	m.substrates = nil
	m.mu.Unlock()
	var result error
	for _, substrate := range substrates {
		result = errors.Join(result, substrate.Close())
	}
	return result
}

// Package relaypmtu measures the non-fragmenting UDP path to a relay region.
package relaypmtu

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/udpsocket"
)

const (
	MinimumSize = 1200
	MaximumSize = 1500
	headerSize  = 26
	tagSize     = sha256.Size
	version     = 1
	kindRequest = 1
	kindReply   = 2
)

var (
	magic      = [4]byte{'P', 'B', 'M', 'T'}
	ErrInvalid = errors.New("invalid relay PMTU probe")
)

type Prober struct {
	sockets    *udpsocket.Set
	connection *net.UDPConn
	remote     *net.UDPAddr
	token      string
	maximum    uint16
	now        func() time.Time
}

func Open(ctx context.Context, endpoint, token string, maximum uint16) (*Prober, error) {
	if ctx == nil || token == "" || len(token) > MaximumSize-headerSize-tagSize || maximum < MinimumSize || maximum > MaximumSize {
		return nil, ErrInvalid
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "udp" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalid
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrInvalid
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", parsed.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, networkadaptation.ErrPMTUProbeUnreachable
	}
	var remote *net.UDPAddr
	for _, address := range addresses {
		if address.Is4() || address.Is6() {
			remote = &net.UDPAddr{IP: net.IP(address.AsSlice()), Port: port}
			break
		}
	}
	if remote == nil {
		return nil, networkadaptation.ErrPMTUProbeUnreachable
	}
	sockets, err := udpsocket.Open(ctx, udpsocket.DevelopmentConfig(remote.IP.To4() != nil, remote.IP.To4() == nil))
	if err != nil {
		return nil, err
	}
	connection := sockets.IPv6()
	if remote.IP.To4() != nil {
		connection = sockets.IPv4()
	}
	// The selected connection owns the set's only socket for this address family.
	return &Prober{sockets: sockets, connection: connection, remote: remote, token: token, maximum: maximum, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (p *Prober) ProbePayload(ctx context.Context, size uint16) (networkadaptation.PMTUProbeResult, error) {
	if p == nil || ctx == nil || p.connection == nil || p.remote == nil || size < MinimumSize || size > p.maximum {
		return networkadaptation.PMTUProbeResult{}, ErrInvalid
	}
	request, err := buildRequest(p.token, int(size))
	if err != nil {
		return networkadaptation.PMTUProbeResult{}, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return networkadaptation.PMTUProbeResult{}, ErrInvalid
	}
	if err := p.connection.SetDeadline(deadline); err != nil {
		return networkadaptation.PMTUProbeResult{}, err
	}
	if _, err := p.connection.WriteToUDP(request, p.remote); err != nil {
		if ctx.Err() != nil {
			return networkadaptation.PMTUProbeResult{}, ctx.Err()
		}
		return networkadaptation.PMTUProbeResult{At: p.now()}, nil
	}
	response := make([]byte, size)
	n, source, err := p.connection.ReadFromUDP(response)
	if err != nil {
		if ctx.Err() != nil {
			return networkadaptation.PMTUProbeResult{}, ctx.Err()
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return networkadaptation.PMTUProbeResult{At: p.now()}, nil
		}
		return networkadaptation.PMTUProbeResult{}, err
	}
	if !source.IP.Equal(p.remote.IP) || source.Port != p.remote.Port || parseResponse(response[:n], request, p.token) != nil {
		return networkadaptation.PMTUProbeResult{}, ErrInvalid
	}
	return networkadaptation.PMTUProbeResult{Supported: true, At: p.now()}, nil
}

func (p *Prober) Close() error {
	if p == nil || p.connection == nil {
		return nil
	}
	err := p.sockets.Close()
	p.connection = nil
	p.sockets = nil
	p.token = ""
	return err
}

func buildRequest(token string, size int) ([]byte, error) {
	if token == "" || len(token) > MaximumSize-headerSize-tagSize || size < MinimumSize || size > MaximumSize || headerSize+len(token)+tagSize > size {
		return nil, ErrInvalid
	}
	frame := make([]byte, size)
	copy(frame[:4], magic[:])
	frame[4], frame[5] = version, kindRequest
	binary.BigEndian.PutUint16(frame[6:8], uint16(size))
	if _, err := rand.Read(frame[8:24]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(frame[24:26], uint16(len(token)))
	copy(frame[headerSize:], token)
	return frame, nil
}

func parseResponse(response, request []byte, token string) error {
	if len(response) != len(request) || len(response) < MinimumSize || len(response) > MaximumSize || subtle.ConstantTimeCompare(response[:4], magic[:]) != 1 || response[4] != version || response[5] != kindReply || int(binary.BigEndian.Uint16(response[6:8])) != len(response) || subtle.ConstantTimeCompare(response[8:24], request[8:24]) != 1 {
		return ErrInvalid
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(response[:len(response)-tagSize])
	if !hmac.Equal(response[len(response)-tagSize:], mac.Sum(nil)) {
		return ErrInvalid
	}
	return nil
}

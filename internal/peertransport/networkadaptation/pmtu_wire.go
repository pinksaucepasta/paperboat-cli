package networkadaptation

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"
)

const (
	pmtuFrameVersion  = 1
	pmtuFrameRequest  = 1
	pmtuFrameResponse = 2
	pmtuHeaderSize    = 24
	pmtuTagSize       = sha256.Size
)

var pmtuFrameMagic = [4]byte{'P', 'B', 'M', 'T'}
var ErrPMTUProbeUnreachable = errors.New("authenticated PMTU probe unreachable")

// PMTUDatagramExchanger sends one exact datagram on the selected path and
// returns its response. Implementations own DF/packet-too-big controls and
// return ErrPMTUProbeUnreachable only for a bounded reachability timeout.
type PMTUDatagramExchanger interface {
	ExchangePMTU(context.Context, []byte) ([]byte, error)
}

type AuthenticatedPMTUProber struct {
	exchanger PMTUDatagramExchanger
	maximum   uint16
	random    io.Reader

	mu       sync.Mutex
	randomMu sync.Mutex
	key      []byte
	closed   bool
}

func NewAuthenticatedPMTUProber(key []byte, maximum uint16, exchanger PMTUDatagramExchanger) (*AuthenticatedPMTUProber, error) {
	if len(key) < sha256.Size || maximum < 1200 || nilPMTUExchanger(exchanger) {
		return nil, ErrInvalid
	}
	return &AuthenticatedPMTUProber{exchanger: exchanger, maximum: maximum, random: rand.Reader, key: append([]byte(nil), key...)}, nil
}

func (p *AuthenticatedPMTUProber) ProbePayload(ctx context.Context, size uint16) (PMTUProbeResult, error) {
	if p == nil || ctx == nil || size < 1200 || size > p.maximum {
		return PMTUProbeResult{}, ErrInvalid
	}
	key, err := p.keyCopy()
	if err != nil {
		return PMTUProbeResult{}, err
	}
	defer zeroBytes(key)
	var nonce [16]byte
	p.randomMu.Lock()
	_, randomErr := io.ReadFull(p.random, nonce[:])
	p.randomMu.Unlock()
	if randomErr != nil {
		return PMTUProbeResult{}, randomErr
	}
	request, err := buildPMTUFrame(key, pmtuFrameRequest, size, nonce)
	if err != nil {
		return PMTUProbeResult{}, err
	}
	response, err := p.exchanger.ExchangePMTU(ctx, request)
	zeroBytes(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return PMTUProbeResult{}, ctxErr
		}
		if errors.Is(err, ErrPMTUProbeUnreachable) {
			return PMTUProbeResult{At: time.Now().UTC()}, nil
		}
		return PMTUProbeResult{}, err
	}
	responseNonce, err := parsePMTUFrame(key, response, pmtuFrameResponse, size)
	zeroBytes(response)
	if err != nil {
		return PMTUProbeResult{}, err
	}
	if responseNonce != nonce {
		return PMTUProbeResult{}, errors.New("PMTU probe nonce mismatch")
	}
	return PMTUProbeResult{Supported: true, At: time.Now().UTC()}, nil
}

func (p *AuthenticatedPMTUProber) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		zeroBytes(p.key)
		p.key = nil
	}
	p.mu.Unlock()
	return nil
}

func (p *AuthenticatedPMTUProber) keyCopy() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.key) < sha256.Size {
		return nil, errors.New("authenticated PMTU prober closed")
	}
	return append([]byte(nil), p.key...), nil
}

type PMTUResponder struct {
	maximum uint16
	mu      sync.Mutex
	key     []byte
	closed  bool
}

func NewPMTUResponder(key []byte, maximum uint16) (*PMTUResponder, error) {
	if len(key) < sha256.Size || maximum < 1200 {
		return nil, ErrInvalid
	}
	return &PMTUResponder{maximum: maximum, key: append([]byte(nil), key...)}, nil
}

func (r *PMTUResponder) Handle(datagram []byte) ([]byte, error) {
	if r == nil || len(datagram) < 1200 || len(datagram) > int(r.maximum) {
		return nil, ErrInvalid
	}
	key, err := r.keyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	size := uint16(len(datagram))
	nonce, err := parsePMTUFrame(key, datagram, pmtuFrameRequest, size)
	if err != nil {
		return nil, err
	}
	return buildPMTUFrame(key, pmtuFrameResponse, size, nonce)
}

func (r *PMTUResponder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		zeroBytes(r.key)
		r.key = nil
	}
	r.mu.Unlock()
	return nil
}

func (r *PMTUResponder) keyCopy() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.key) < sha256.Size {
		return nil, errors.New("PMTU responder closed")
	}
	return append([]byte(nil), r.key...), nil
}

func buildPMTUFrame(key []byte, kind byte, size uint16, nonce [16]byte) ([]byte, error) {
	if len(key) < sha256.Size || size < pmtuHeaderSize+pmtuTagSize || kind != pmtuFrameRequest && kind != pmtuFrameResponse {
		return nil, ErrInvalid
	}
	frame := make([]byte, int(size))
	copy(frame[:4], pmtuFrameMagic[:])
	frame[4], frame[5] = pmtuFrameVersion, kind
	binary.BigEndian.PutUint16(frame[6:8], size)
	copy(frame[8:pmtuHeaderSize], nonce[:])
	tagOffset := len(frame) - pmtuTagSize
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame[:tagOffset])
	copy(frame[tagOffset:], mac.Sum(nil))
	return frame, nil
}

func parsePMTUFrame(key, frame []byte, kind byte, size uint16) ([16]byte, error) {
	if len(key) < sha256.Size || len(frame) != int(size) || len(frame) < pmtuHeaderSize+pmtuTagSize {
		return [16]byte{}, errors.New("invalid PMTU probe frame size")
	}
	tagOffset := len(frame) - pmtuTagSize
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame[:tagOffset])
	if !hmac.Equal(frame[tagOffset:], mac.Sum(nil)) {
		return [16]byte{}, errors.New("invalid PMTU probe authentication")
	}
	if string(frame[:4]) != string(pmtuFrameMagic[:]) || frame[4] != pmtuFrameVersion || frame[5] != kind || binary.BigEndian.Uint16(frame[6:8]) != size {
		return [16]byte{}, errors.New("invalid PMTU probe header")
	}
	var nonce [16]byte
	copy(nonce[:], frame[8:pmtuHeaderSize])
	return nonce, nil
}

func nilPMTUExchanger(exchanger PMTUDatagramExchanger) bool {
	if exchanger == nil {
		return true
	}
	value := reflect.ValueOf(exchanger)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

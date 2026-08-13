package relaynoise

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	headerLength         = 28
	maximumCiphertext    = 65535
	authenticationBytes  = 16
	maximumPlaintext     = maximumCiphertext - authenticationBytes
	softRekeyBytes       = 900 << 20
	hardRekeyBytes       = 1 << 30
	softRekeyAge         = 55 * time.Minute
	hardRekeyAge         = time.Hour
	sequenceRekeyReserve = uint64(16)
	softRekeySequence    = math.MaxUint64 - 2*sequenceRekeyReserve
	hardRekeySequence    = math.MaxUint64 - sequenceRekeyReserve
	flagResponder        = 1 << 0
	flagClose            = 1 << 1
	knownFlags           = flagResponder | flagClose
)

type Session struct {
	initiator      bool
	handle         [16]byte
	bindingMu      sync.RWMutex
	channelBinding [32]byte
	send           direction
	receive        direction
	poisonMu       sync.RWMutex
	poisoned       bool
	rekeyPolicy    RekeyPolicy
	rekeyEvents    chan struct{}
}

var ErrRekeyRequired = errors.New("relay E2EE rekey required")

type RekeyPolicy struct {
	Bytes     uint64
	HardBytes uint64
	SoftAge   time.Duration
	HardAge   time.Duration
}

func DevelopmentRekeyPolicy() RekeyPolicy {
	return RekeyPolicy{Bytes: softRekeyBytes, HardBytes: hardRekeyBytes, SoftAge: softRekeyAge, HardAge: hardRekeyAge}
}

func (p RekeyPolicy) valid() bool {
	return p.Bytes > 0 && p.HardBytes >= p.Bytes && p.SoftAge > 0 && p.HardAge >= p.SoftAge
}

type direction struct {
	mu       sync.Mutex
	cipher   *noise.CipherState
	sequence uint64
	closed   bool
	bytes    uint64
	started  time.Time
}

func newSession(initiator bool, handle [16]byte, send, receive *noise.CipherState, binding []byte) *Session {
	var channelBinding [32]byte
	copy(channelBinding[:], binding)
	now := time.Now()
	return &Session{initiator: initiator, handle: handle, channelBinding: channelBinding, send: direction{cipher: send, started: now}, receive: direction{cipher: receive, started: now}, rekeyPolicy: DevelopmentRekeyPolicy(), rekeyEvents: make(chan struct{}, 1)}
}

func (s *Session) ChannelBinding() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	return s.channelBinding
}

func (s *Session) setChannelBinding(binding [32]byte) {
	s.bindingMu.Lock()
	s.channelBinding = binding
	s.bindingMu.Unlock()
}

func (s *Session) ConfigureRekeyPolicy(policy RekeyPolicy) error {
	defaults := DevelopmentRekeyPolicy()
	if s == nil || !policy.valid() || policy.Bytes > defaults.Bytes || policy.HardBytes > defaults.HardBytes || policy.SoftAge > defaults.SoftAge || policy.HardAge > defaults.HardAge {
		return errors.New("invalid relay E2EE rekey policy")
	}
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	s.receive.mu.Lock()
	defer s.receive.mu.Unlock()
	if s.send.sequence != 0 || s.receive.sequence != 0 || s.send.bytes != 0 || s.receive.bytes != 0 {
		return errors.New("relay E2EE rekey policy cannot change after records")
	}
	s.rekeyPolicy = policy
	return nil
}

func (s *Session) Seal(plaintext []byte, closeAfter bool) ([]byte, error) {
	if s.isPoisoned() {
		return nil, ErrProtocol
	}
	if len(plaintext) > maximumPlaintext {
		return nil, ErrLimit
	}
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	return s.sealLocked(plaintext, closeAfter, false)
}

func (s *Session) sealLocked(plaintext []byte, closeAfter, rekeyControl bool) ([]byte, error) {
	if s.send.closed || s.send.cipher == nil {
		return nil, ErrProtocol
	}
	if s.rekeyRequiredLocked(s.send.sequence, s.send.bytes, s.send.started, len(plaintext), rekeyControl) {
		s.signalRekeyLocked(s.send.sequence, s.send.bytes, s.send.started)
		return nil, ErrRekeyRequired
	}
	flags := byte(0)
	if !s.initiator {
		flags |= flagResponder
	}
	if closeAfter {
		flags |= flagClose
	}
	header := makeHeader(flags, s.handle, s.send.sequence, uint16(len(plaintext)+authenticationBytes))
	ciphertext, err := s.send.cipher.Encrypt(nil, header, plaintext)
	if err != nil || len(ciphertext) != len(plaintext)+authenticationBytes {
		s.poison()
		return nil, errors.New("encrypt relay E2EE record")
	}
	record := append(header, ciphertext...)
	s.send.sequence++
	s.send.bytes += uint64(len(plaintext))
	s.signalRekeyLocked(s.send.sequence, s.send.bytes, s.send.started)
	s.send.closed = closeAfter
	return record, nil
}

func (s *Session) sealAndSend(ctx context.Context, plaintext []byte, closeAfter, rekeyControl bool, send func([]byte) error) error {
	if s == nil || ctx == nil || send == nil || s.isPoisoned() {
		return ErrProtocol
	}
	if len(plaintext) > maximumPlaintext {
		return ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.send.mu.Lock()
	defer s.send.mu.Unlock()
	record, err := s.sealLocked(plaintext, closeAfter, rekeyControl)
	if err != nil {
		return err
	}
	if err := send(record); err != nil {
		s.poison()
		return err
	}
	return nil
}

func (s *Session) Open(record []byte) ([]byte, bool, error) {
	if s.isPoisoned() {
		return nil, false, ErrProtocol
	}
	if len(record) < headerLength || len(record) > headerLength+maximumCiphertext {
		s.poison()
		return nil, false, ErrLimit
	}
	header := record[:headerLength]
	if header[0] != recordVersion || header[1]&^knownFlags != 0 || !bytes.Equal(header[2:18], s.handle[:]) {
		s.poison()
		return nil, false, ErrProtocol
	}
	expectedResponder := s.initiator
	if (header[1]&flagResponder != 0) != expectedResponder {
		s.poison()
		return nil, false, ErrProtocol
	}
	length := int(binary.BigEndian.Uint16(header[26:28]))
	if length < authenticationBytes || length != len(record)-headerLength {
		s.poison()
		return nil, false, ErrProtocol
	}
	s.receive.mu.Lock()
	defer s.receive.mu.Unlock()
	if s.receive.closed || s.receive.cipher == nil {
		return nil, false, ErrProtocol
	}
	if s.receive.sequence == math.MaxUint64 {
		s.poison()
		return nil, false, ErrRekeyRequired
	}
	if binary.BigEndian.Uint64(header[18:26]) != s.receive.sequence {
		s.poison()
		return nil, false, ErrReplay
	}
	plaintext, err := s.receive.cipher.Decrypt(nil, header, record[headerLength:])
	if err != nil {
		s.poison()
		return nil, false, ErrAuthentication
	}
	if s.rekeyRequiredLocked(s.receive.sequence, s.receive.bytes, s.receive.started, len(plaintext), true) {
		clear(plaintext)
		s.poison()
		return nil, false, ErrRekeyRequired
	}
	closeAfter := header[1]&flagClose != 0
	s.receive.sequence++
	s.receive.bytes += uint64(len(plaintext))
	s.signalRekeyLocked(s.receive.sequence, s.receive.bytes, s.receive.started)
	s.receive.closed = closeAfter
	return plaintext, closeAfter, nil
}

func (s *Session) RekeyNeeded() bool {
	if s == nil || !s.rekeyPolicy.valid() {
		return true
	}
	s.send.mu.Lock()
	s.receive.mu.Lock()
	needed := s.send.sequence >= softRekeySequence || s.receive.sequence >= softRekeySequence || s.send.bytes >= s.rekeyPolicy.Bytes || s.receive.bytes >= s.rekeyPolicy.Bytes || time.Since(s.send.started) >= s.rekeyPolicy.SoftAge || time.Since(s.receive.started) >= s.rekeyPolicy.SoftAge
	s.receive.mu.Unlock()
	s.send.mu.Unlock()
	return needed
}

func (s *Session) RekeyEvents() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.rekeyEvents
}

func (s *Session) NextRekeyDelay() time.Duration {
	if s == nil || !s.rekeyPolicy.valid() {
		return 0
	}
	s.send.mu.Lock()
	s.receive.mu.Lock()
	if s.send.sequence >= softRekeySequence || s.receive.sequence >= softRekeySequence {
		s.receive.mu.Unlock()
		s.send.mu.Unlock()
		return 0
	}
	deadline := s.send.started.Add(s.rekeyPolicy.SoftAge)
	if receiveDeadline := s.receive.started.Add(s.rekeyPolicy.SoftAge); receiveDeadline.Before(deadline) {
		deadline = receiveDeadline
	}
	s.receive.mu.Unlock()
	s.send.mu.Unlock()
	if delay := time.Until(deadline); delay > 0 {
		return delay
	}
	return 0
}

func (s *Session) signalRekeyLocked(sequence, bytes uint64, started time.Time) {
	if sequence < softRekeySequence && bytes < s.rekeyPolicy.Bytes && time.Since(started) < s.rekeyPolicy.SoftAge {
		return
	}
	select {
	case s.rekeyEvents <- struct{}{}:
	default:
	}
}

func (s *Session) rekeyRequiredLocked(sequence, bytes uint64, started time.Time, plaintextLength int, rekeyControl bool) bool {
	return sequence == math.MaxUint64 || !rekeyControl && sequence >= hardRekeySequence || !s.rekeyPolicy.valid() || started.IsZero() || bytes >= s.rekeyPolicy.HardBytes || uint64(plaintextLength) > s.rekeyPolicy.HardBytes-bytes || time.Since(started) >= s.rekeyPolicy.HardAge
}

func (s *Session) poison() {
	s.poisonMu.Lock()
	s.poisoned = true
	s.poisonMu.Unlock()
}

func (s *Session) isPoisoned() bool {
	s.poisonMu.RLock()
	defer s.poisonMu.RUnlock()
	return s.poisoned
}

func makeHeader(flags byte, handle [16]byte, sequence uint64, length uint16) []byte {
	header := make([]byte, headerLength)
	header[0] = recordVersion
	header[1] = flags
	copy(header[2:18], handle[:])
	binary.BigEndian.PutUint64(header[18:26], sequence)
	binary.BigEndian.PutUint16(header[26:28], length)
	return header
}

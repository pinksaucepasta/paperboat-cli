package relaynoise

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const rekeyMarkerSize = 4 + 1 + 1 + 1 + 8 + 32
const rekeyHandshakeHeaderSize = 4 + 1 + 1 + 8 + 32 + 2

var ErrRekeyMarker = errors.New("invalid relay E2EE rekey marker")

type RekeyHandshakeKind uint8

const (
	RekeyHandshakeRequest  RekeyHandshakeKind = 1
	RekeyHandshakeResponse RekeyHandshakeKind = 2
)

type RekeyHandshakeControl struct {
	Kind       RekeyHandshakeKind
	Generation uint64
	Binding    [32]byte
	Message    []byte
}

func (c RekeyHandshakeControl) MarshalBinary() ([]byte, error) {
	if (c.Kind != RekeyHandshakeRequest && c.Kind != RekeyHandshakeResponse) || c.Generation == 0 || allZero(c.Binding[:]) || len(c.Message) == 0 || len(c.Message) > maximumPlaintext-rekeyHandshakeHeaderSize {
		return nil, ErrRekeyMarker
	}
	result := make([]byte, rekeyHandshakeHeaderSize+len(c.Message))
	copy(result[:4], []byte{'P', 'B', 'R', 'H'})
	result[4] = recordVersion
	result[5] = byte(c.Kind)
	binary.BigEndian.PutUint64(result[6:14], c.Generation)
	copy(result[14:46], c.Binding[:])
	binary.BigEndian.PutUint16(result[46:48], uint16(len(c.Message)))
	copy(result[48:], c.Message)
	return result, nil
}

func ParseRekeyHandshakeControl(value []byte, expectedKind RekeyHandshakeKind, expectedGeneration uint64, expectedBinding [32]byte) (RekeyHandshakeControl, error) {
	var control RekeyHandshakeControl
	if len(value) < rekeyHandshakeHeaderSize || len(value) > maximumPlaintext || string(value[:4]) != "PBRH" || value[4] != recordVersion || value[5] != byte(expectedKind) || expectedGeneration == 0 || allZero(expectedBinding[:]) {
		return control, ErrRekeyMarker
	}
	control.Kind = RekeyHandshakeKind(value[5])
	control.Generation = binary.BigEndian.Uint64(value[6:14])
	copy(control.Binding[:], value[14:46])
	length := int(binary.BigEndian.Uint16(value[46:48]))
	if control.Generation != expectedGeneration || control.Binding != expectedBinding || length == 0 || length != len(value)-rekeyHandshakeHeaderSize {
		return RekeyHandshakeControl{}, ErrRekeyMarker
	}
	control.Message = append([]byte(nil), value[48:]...)
	return control, nil
}

func NewRekeyInitiator(local noise.DHKey, responderPublic [32]byte, prologue Prologue, handle [16]byte, priorBinding [32]byte, generation uint64) (*Initiator, error) {
	if err := validateKeypair(local); err != nil || allZero(responderPublic[:]) || allZero(handle[:]) {
		return nil, errors.New("invalid Noise rekey initiator identity or handle")
	}
	encoded, err := marshalRekeyPrologue(prologue, priorBinding, generation)
	if err != nil {
		return nil, err
	}
	return newInitiator(local, responderPublic, encoded, handle)
}

func NewRekeyResponder(local noise.DHKey, initiatorPublic [32]byte, prologue Prologue, handle [16]byte, priorBinding [32]byte, generation uint64) (*Responder, error) {
	if err := validateKeypair(local); err != nil || allZero(initiatorPublic[:]) || allZero(handle[:]) {
		return nil, errors.New("invalid Noise rekey responder identity or handle")
	}
	encoded, err := marshalRekeyPrologue(prologue, priorBinding, generation)
	if err != nil {
		return nil, err
	}
	return newResponder(local, initiatorPublic, encoded, handle)
}

func marshalRekeyPrologue(prologue Prologue, priorBinding [32]byte, generation uint64) ([]byte, error) {
	if allZero(priorBinding[:]) || generation == 0 {
		return nil, ErrRekeyMarker
	}
	encoded, err := prologue.MarshalBinary()
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, 'P', 'B', 'R', 'P')
	encoded = binary.BigEndian.AppendUint64(encoded, generation)
	return append(encoded, priorBinding[:]...), nil
}

type RekeyDirection uint8
type RekeyMarkerKind uint8

const (
	RekeyInitiatorToResponder RekeyDirection = 1
	RekeyResponderToInitiator RekeyDirection = 2
)

const (
	RekeyCommit          RekeyMarkerKind = 1
	RekeyAcknowledgement RekeyMarkerKind = 2
)

type RekeyMarker struct {
	Generation uint64
	Direction  RekeyDirection
	Kind       RekeyMarkerKind
	Binding    [32]byte
}

type rekeyDirectionState struct {
	commit bool
	ack    bool
}

type RekeyExchange struct {
	mu         sync.Mutex
	binding    [32]byte
	generation uint64
	directions [2]rekeyDirectionState
}

type RekeyTransition struct {
	mu         sync.Mutex
	current    *Session
	next       *Session
	exchange   *RekeyExchange
	generation uint64
	switched   [2]bool
}

func NewRekeyTransition(current, next *Session, generation uint64) (*RekeyTransition, error) {
	if current == nil || next == nil {
		return nil, ErrRekeyMarker
	}
	currentBinding, nextBinding := current.ChannelBinding(), next.ChannelBinding()
	if current == next || generation == 0 || current.initiator != next.initiator || current.handle != next.handle || currentBinding == nextBinding || allZero(currentBinding[:]) || allZero(nextBinding[:]) {
		return nil, ErrRekeyMarker
	}
	exchange, err := NewRekeyExchange(currentBinding, generation)
	if err != nil {
		return nil, err
	}
	return &RekeyTransition{current: current, next: next, exchange: exchange, generation: generation}, nil
}

func (t *RekeyTransition) Accept(marker RekeyMarker) (bool, error) {
	if t == nil || t.current == nil || t.next == nil || t.exchange == nil {
		return false, ErrRekeyMarker
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	complete, err := t.exchange.Accept(marker)
	if err != nil {
		return false, err
	}
	index := int(marker.Direction) - 1
	if marker.Kind == RekeyAcknowledgement {
		if t.switched[index] {
			return false, ErrRekeyMarker
		}
		if err := t.current.installRekeyDirection(t.next, marker.Direction); err != nil {
			return false, err
		}
		t.switched[index] = true
	}
	if complete {
		if !t.switched[0] || !t.switched[1] {
			return false, ErrRekeyMarker
		}
		t.current.setChannelBinding(t.next.ChannelBinding())
		t.next = nil
	}
	return complete, nil
}

func (s *Session) installRekeyDirection(next *Session, rekeyDirection RekeyDirection) error {
	useSend := s.initiator && rekeyDirection == RekeyInitiatorToResponder || !s.initiator && rekeyDirection == RekeyResponderToInitiator
	currentDirection, nextDirection := &s.receive, &next.receive
	if useSend {
		currentDirection, nextDirection = &s.send, &next.send
	}
	currentDirection.mu.Lock()
	defer currentDirection.mu.Unlock()
	nextDirection.mu.Lock()
	defer nextDirection.mu.Unlock()
	if currentDirection.closed || currentDirection.cipher == nil || nextDirection.closed || nextDirection.cipher == nil || nextDirection.sequence != 0 || nextDirection.bytes != 0 {
		return ErrRekeyMarker
	}
	currentDirection.cipher = nextDirection.cipher
	currentDirection.sequence = 0
	currentDirection.bytes = 0
	currentDirection.started = time.Now()
	nextDirection.cipher = nil
	return nil
}

func NewRekeyExchange(binding [32]byte, generation uint64) (*RekeyExchange, error) {
	if allZero(binding[:]) || generation == 0 {
		return nil, ErrRekeyMarker
	}
	return &RekeyExchange{binding: binding, generation: generation}, nil
}

func (e *RekeyExchange) Accept(marker RekeyMarker) (bool, error) {
	if e == nil {
		return false, ErrRekeyMarker
	}
	encoded, err := marker.MarshalBinary()
	if err != nil {
		return false, err
	}
	parsed, err := ParseRekeyMarker(encoded, e.binding, marker.Direction, marker.Kind, e.generation)
	if err != nil || parsed.Generation != e.generation {
		return false, ErrRekeyMarker
	}
	index := int(marker.Direction) - 1
	e.mu.Lock()
	defer e.mu.Unlock()
	state := &e.directions[index]
	switch marker.Kind {
	case RekeyCommit:
		if state.commit || state.ack {
			return false, ErrRekeyMarker
		}
		state.commit = true
	case RekeyAcknowledgement:
		if !state.commit || state.ack {
			return false, ErrRekeyMarker
		}
		state.ack = true
	default:
		return false, ErrRekeyMarker
	}
	return e.directions[0].ack && e.directions[1].ack, nil
}

func (m RekeyMarker) MarshalBinary() ([]byte, error) {
	if m.Generation == 0 || (m.Direction != RekeyInitiatorToResponder && m.Direction != RekeyResponderToInitiator) || (m.Kind != RekeyCommit && m.Kind != RekeyAcknowledgement) || allZero(m.Binding[:]) {
		return nil, ErrRekeyMarker
	}
	result := make([]byte, rekeyMarkerSize)
	copy(result[:4], []byte{'P', 'B', 'R', 'K'})
	result[4] = recordVersion
	result[5] = byte(m.Direction)
	result[6] = byte(m.Kind)
	binary.BigEndian.PutUint64(result[7:15], m.Generation)
	copy(result[15:], m.Binding[:])
	return result, nil
}

func ParseRekeyMarker(value []byte, expectedBinding [32]byte, expectedDirection RekeyDirection, expectedKind RekeyMarkerKind, minimumGeneration uint64) (RekeyMarker, error) {
	var marker RekeyMarker
	if len(value) != rekeyMarkerSize || string(value[:4]) != "PBRK" || value[4] != recordVersion || value[5] != byte(expectedDirection) || value[6] != byte(expectedKind) || allZero(expectedBinding[:]) {
		return marker, ErrRekeyMarker
	}
	marker.Direction = RekeyDirection(value[5])
	marker.Kind = RekeyMarkerKind(value[6])
	marker.Generation = binary.BigEndian.Uint64(value[7:15])
	copy(marker.Binding[:], value[15:])
	if marker.Generation < minimumGeneration || !bytes.Equal(marker.Binding[:], expectedBinding[:]) {
		return RekeyMarker{}, ErrRekeyMarker
	}
	return marker, nil
}

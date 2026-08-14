package candidatelease

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const maxControlMessage = 64 << 10

func Frame(m Message) ([]byte, error) {
	payload, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	if len(payload) > maxControlMessage {
		return nil, ErrProtocol
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame, nil
}

func Unframe(raw []byte) (Message, error) {
	if len(raw) < 4 || binary.BigEndian.Uint32(raw[:4]) != uint32(len(raw)-4) || len(raw)-4 > maxControlMessage {
		return Message{}, ErrProtocol
	}
	return Parse(raw[4:])
}

func FrameReader(r io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxControlMessage {
		return Message{}, ErrProtocol
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Message{}, err
	}
	return Parse(payload)
}

func FrameBytes(m Message) ([]byte, error) { return Frame(m) }

var ErrProtocol = errors.New("invalid candidate lease message")

type MessageType string

const (
	Adopt         MessageType = "candidate_adopt"
	AdoptAck      MessageType = "candidate_adopt_ack"
	Release       MessageType = "candidate_release"
	ReleaseAck    MessageType = "candidate_release_ack"
	AttemptSettle MessageType = "attempt_settle"
)

type Message struct {
	Version         uint8       `json:"version"`
	Type            MessageType `json:"type"`
	Candidate       ID          `json:"candidate_id"`
	LeaseGeneration uint64      `json:"lease_generation"`
	Candidates      []ID        `json:"candidates,omitempty"`
}

func (m Message) Marshal() ([]byte, error) {
	if m.Version != 1 || m.Type == "" || m.Candidate == "" && m.Type != AttemptSettle {
		return nil, ErrProtocol
	}
	if (m.Type == Adopt || m.Type == Release || m.Type == AdoptAck || m.Type == ReleaseAck) && m.LeaseGeneration == 0 {
		return nil, ErrProtocol
	}
	return json.Marshal(m)
}

func Parse(raw []byte) (Message, error) {
	var m Message
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m.Version != 1 || m.Type == "" {
		return Message{}, ErrProtocol
	}
	if m.Type != AttemptSettle && m.Candidate == "" {
		return Message{}, ErrProtocol
	}
	if m.Type != AttemptSettle && m.LeaseGeneration == 0 {
		return Message{}, ErrProtocol
	}
	return m, nil
}

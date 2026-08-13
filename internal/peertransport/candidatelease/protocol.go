package candidatelease

import (
	"encoding/json"
	"errors"
)

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

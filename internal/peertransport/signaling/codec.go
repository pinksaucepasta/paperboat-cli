// Package signaling defines the bounded, typed ICE signaling messages shared
// by Paperboat endpoints. Transport admission and authorization remain owned
// by the server and tunnel; this package only validates the message boundary.
package signaling

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/iceagent"
)

const (
	Schema            = "paperboat.peer-signaling/v1"
	MaximumMessage    = 16 << 10
	MaximumCandidate  = iceagent.MaximumCandidateBytes
	MaximumCandidates = iceagent.MaximumCandidates
)

var (
	ErrInvalid  = errors.New("invalid peer signaling message")
	ErrStale    = errors.New("stale peer signaling generation")
	ErrSequence = errors.New("peer signaling sequence is invalid")
	ErrLimit    = errors.New("peer signaling limit exceeded")
	ErrClosed   = errors.New("peer signaling session is closed")
)

type Role string

const (
	RoleControlling Role = "controlling"
	RoleControlled  Role = "controlled"
)

type Kind string

const (
	KindCredentials Kind = "credentials"
	KindCandidate   Kind = "candidate"
	KindEnd         Kind = "end"
	KindReady       Kind = "ready"
	KindClose       Kind = "close"
)

// Message is deliberately closed-world: adding a new required kind requires a
// protocol decision instead of being silently accepted by old endpoints.
type Message struct {
	Schema            string `json:"schema"`
	IntentID          string `json:"intent_id"`
	AttemptGeneration uint64 `json:"attempt_generation"`
	NetworkGeneration uint64 `json:"network_generation"`
	Role              Role   `json:"role"`
	Sequence          uint64 `json:"sequence"`
	Kind              Kind   `json:"kind"`
	Ufrag             string `json:"ufrag,omitempty"`
	Password          string `json:"password,omitempty"`
	Candidate         string `json:"candidate,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

type Binding struct {
	IntentID          string
	AttemptGeneration uint64
	NetworkGeneration uint64
	Role              Role
}

func (b Binding) valid() bool {
	return boundedID(b.IntentID) && b.AttemptGeneration > 0 && b.NetworkGeneration > 0 && validRole(b.Role)
}

func (m Message) Validate(binding Binding) error {
	if !binding.valid() || m.Schema != Schema || m.IntentID != binding.IntentID || m.Sequence == 0 || !validKind(m.Kind) {
		return ErrInvalid
	}
	if m.AttemptGeneration != binding.AttemptGeneration || m.NetworkGeneration != binding.NetworkGeneration {
		return ErrStale
	}
	if m.Role != binding.Role {
		return ErrInvalid
	}
	switch m.Kind {
	case KindCredentials:
		if !validCredential(m.Ufrag, m.Password) || m.Candidate != "" || m.Reason != "" {
			return ErrInvalid
		}
	case KindCandidate:
		if m.Ufrag != "" || m.Password != "" || m.Reason != "" || len(m.Candidate) == 0 || len(m.Candidate) > MaximumCandidate {
			return ErrInvalid
		}
		if err := iceagent.ValidateCandidateString(m.Candidate); err != nil {
			return ErrInvalid
		}
	case KindEnd, KindReady:
		if m.Ufrag != "" || m.Password != "" || m.Candidate != "" || m.Reason != "" {
			return ErrInvalid
		}
	case KindClose:
		if m.Ufrag != "" || m.Password != "" || m.Candidate != "" || !validReason(m.Reason) {
			return ErrInvalid
		}
	}
	return nil
}

func Encode(message Message, binding Binding) ([]byte, error) {
	if err := message.Validate(binding); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(message)
	if err != nil || len(encoded) > MaximumMessage {
		return nil, ErrLimit
	}
	return encoded, nil
}

func Decode(raw []byte, binding Binding) (Message, error) {
	if len(raw) == 0 || len(raw) > MaximumMessage {
		return Message{}, ErrLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var message Message
	if err := decoder.Decode(&message); err != nil {
		return Message{}, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Message{}, ErrInvalid
	}
	if err := message.Validate(binding); err != nil {
		return Message{}, err
	}
	canonical, err := json.Marshal(message)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Message{}, ErrInvalid
	}
	return message, nil
}

type Validator struct {
	binding      Binding
	lastSequence uint64
	candidates   map[string]struct{}
	credentials  bool
	ended        bool
	ready        bool
	closed       bool
	maximum      int
}

func NewValidator(binding Binding) (*Validator, error) {
	if !binding.valid() {
		return nil, ErrInvalid
	}
	return &Validator{binding: binding, candidates: make(map[string]struct{}), maximum: MaximumCandidates}, nil
}

func (v *Validator) Accept(raw []byte) (Message, bool, error) {
	if v == nil {
		return Message{}, false, ErrInvalid
	}
	if v.closed {
		return Message{}, false, ErrClosed
	}
	if v.lastSequence == math.MaxUint64 {
		return Message{}, false, ErrSequence
	}
	message, err := Decode(raw, v.binding)
	if err != nil {
		return Message{}, false, err
	}
	if message.Sequence != v.lastSequence+1 {
		return Message{}, false, ErrSequence
	}
	switch message.Kind {
	case KindCredentials:
		if v.credentials || v.ended {
			return Message{}, false, ErrSequence
		}
	case KindCandidate:
		if !v.credentials || v.ended {
			return Message{}, false, ErrSequence
		}
		_, duplicate := v.candidates[message.Candidate]
		if !duplicate && len(v.candidates) >= v.maximum {
			return Message{}, false, ErrLimit
		}
	case KindEnd:
		if !v.credentials || v.ended {
			return Message{}, false, ErrSequence
		}
	case KindReady:
		if !v.credentials || v.ready {
			return Message{}, false, ErrSequence
		}
	}
	v.lastSequence = message.Sequence
	switch message.Kind {
	case KindCredentials:
		v.credentials = true
	case KindCandidate:
		if _, duplicate := v.candidates[message.Candidate]; duplicate {
			return message, false, nil
		}
		v.candidates[message.Candidate] = struct{}{}
		return message, true, nil
	case KindEnd:
		v.ended = true
	case KindReady:
		v.ready = true
	case KindClose:
		v.closed = true
	}
	return message, true, nil
}

func boundedID(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validRole(value Role) bool { return value == RoleControlling || value == RoleControlled }
func validKind(value Kind) bool {
	return value == KindCredentials || value == KindCandidate || value == KindEnd || value == KindReady || value == KindClose
}
func validReason(value string) bool {
	switch value {
	case "completed", "canceled", "network_changed", "expired", "revoked", "protocol_error", "capacity":
		return true
	default:
		return false
	}
}
func validCredential(ufrag, password string) bool {
	return len(ufrag) >= 4 && len(ufrag) <= 256 && len(password) >= 22 && len(password) <= 256 && iceCredentialCharacters(ufrag) && iceCredentialCharacters(password)
}

func iceCredentialCharacters(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '+' || character == '/' {
			continue
		}
		return false
	}
	return true
}

package signaling

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func testBinding() Binding {
	return Binding{IntentID: "intent_01", AttemptGeneration: 3, NetworkGeneration: 7, Role: RoleControlling}
}

func TestCodecRoundTripsTypedMessages(t *testing.T) {
	binding := testBinding()
	cases := []Message{
		{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 1, Kind: KindCredentials, Ufrag: "ufrag01", Password: strings.Repeat("p", 22)},
		{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 2, Kind: KindCandidate, Candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host"},
		{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 3, Kind: KindEnd},
		{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 4, Kind: KindReady},
		{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 5, Kind: KindClose, Reason: "network_changed"},
	}
	validator, err := NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range cases {
		raw, err := Encode(want, binding)
		if err != nil {
			t.Fatalf("encode %s: %v", want.Kind, err)
		}
		got, applied, err := validator.Accept(raw)
		if err != nil || !applied || got != want {
			t.Fatalf("accept got=%+v applied=%t err=%v want=%+v", got, applied, err, want)
		}
	}
	if _, _, err := validator.Accept([]byte(`{"schema":"paperboat.peer-signaling/v1"}`)); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close error=%v", err)
	}
}

func TestValidatorDeduplicatesCandidatesWithoutAdvancingOutOfOrder(t *testing.T) {
	binding := testBinding()
	validator, err := NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	credentials := Message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 1, Kind: KindCredentials, Ufrag: "ufrag01", Password: strings.Repeat("p", 22)}
	raw, _ := Encode(credentials, binding)
	if _, applied, err := validator.Accept(raw); err != nil || !applied {
		t.Fatalf("credentials applied=%t err=%v", applied, err)
	}
	message := Message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 2, Kind: KindCandidate, Candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host"}
	raw, _ = Encode(message, binding)
	if _, applied, err := validator.Accept(raw); err != nil || !applied {
		t.Fatalf("first candidate applied=%t err=%v", applied, err)
	}
	message.Sequence = 3
	raw, _ = Encode(message, binding)
	if _, applied, err := validator.Accept(raw); err != nil || applied {
		t.Fatalf("duplicate applied=%t err=%v", applied, err)
	}
	message.Sequence = 5
	raw, _ = Encode(message, binding)
	if _, _, err := validator.Accept(raw); !errors.Is(err, ErrSequence) {
		t.Fatalf("sequence error=%v", err)
	}
}

func TestCodecRejectsStaleSecretsUnknownFieldsAndForbiddenCandidates(t *testing.T) {
	binding := testBinding()
	valid := Message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 1, Kind: KindCredentials, Ufrag: "ufrag01", Password: strings.Repeat("p", 22)}
	stale := valid
	stale.AttemptGeneration++
	if _, err := Encode(stale, binding); !errors.Is(err, ErrStale) {
		t.Fatalf("stale attempt error=%v", err)
	}
	for name, mutate := range map[string]func(Message) Message{
		"wrong role": func(value Message) Message { value.Role = RoleControlled; return value },
		"credential candidate": func(value Message) Message {
			value.Kind = KindCandidate
			value.Candidate = "candidate:1 1 TCP 1 192.0.2.1 5000 typ host tcptype passive"
			value.Ufrag, value.Password = "", ""
			return value
		},
	} {
		if _, err := Encode(mutate(valid), binding); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	raw := []byte(`{"schema":"paperboat.peer-signaling/v1","intent_id":"intent_01","attempt_generation":3,"network_generation":7,"role":"controlling","sequence":1,"kind":"end","extra":true}`)
	if _, err := Decode(raw, binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field error=%v", err)
	}
	if _, err := Decode(append(raw[:len(raw)-1], '}', 'x'), binding); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data error=%v", err)
	}
	canonical, err := Encode(valid, binding)
	if err != nil {
		t.Fatal(err)
	}
	for name, malformed := range map[string][]byte{
		"duplicate field":    []byte(strings.Replace(string(canonical), `"sequence":1`, `"sequence":1,"sequence":1`, 1)),
		"leading whitespace": append([]byte(" "), canonical...),
	} {
		if _, err := Decode(malformed, binding); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}

func TestValidatorBoundsCandidates(t *testing.T) {
	binding := testBinding()
	validator, err := NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	validator.maximum = 1
	credentials := Message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Sequence: 1, Kind: KindCredentials, Ufrag: "ufrag01", Password: strings.Repeat("p", 22)}
	encoded, encodeErr := Encode(credentials, binding)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if _, _, err := validator.Accept(encoded); err != nil {
		t.Fatal(err)
	}
	base := Message{Schema: Schema, IntentID: binding.IntentID, AttemptGeneration: 3, NetworkGeneration: 7, Role: binding.Role, Kind: KindCandidate}
	for sequence, candidate := range []string{"candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host", "candidate:2 1 UDP 2130706431 192.0.2.2 5001 typ host"} {
		base.Sequence = uint64(sequence + 2)
		base.Candidate = candidate
		raw, encodeErr := Encode(base, binding)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		_, _, acceptErr := validator.Accept(raw)
		if sequence == 1 && !errors.Is(acceptErr, ErrLimit) {
			t.Fatalf("limit error=%v", acceptErr)
		}
	}
	base.Candidate = "candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host"
	raw, err := Encode(base, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := validator.Accept(raw); err != nil || applied {
		t.Fatalf("rejected sequence was committed: applied=%t err=%v", applied, err)
	}
}

func TestValidatorSequenceExhaustionIsPermanent(t *testing.T) {
	binding := testBinding()
	validator, err := NewValidator(binding)
	if err != nil {
		t.Fatal(err)
	}
	validator.lastSequence = math.MaxUint64
	validator.credentials = true
	validator.candidates["candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host"] = struct{}{}

	wantCandidateCount := len(validator.candidates)
	for _, raw := range [][]byte{
		[]byte(`{"schema":"paperboat.peer-signaling/v1"}`),
		[]byte(`{"schema":"paperboat.peer-signaling/v1","intent_id":"intent_01","attempt_generation":3,"network_generation":7,"role":"controlling","sequence":1,"kind":"end"}`),
	} {
		if _, applied, acceptErr := validator.Accept(raw); !errors.Is(acceptErr, ErrSequence) || applied {
			t.Fatalf("accept applied=%t error=%v", applied, acceptErr)
		}
		if validator.lastSequence != math.MaxUint64 || !validator.credentials || validator.ended || validator.closed || len(validator.candidates) != wantCandidateCount {
			t.Fatalf("validator mutated after exhaustion: %+v", validator)
		}
	}
}

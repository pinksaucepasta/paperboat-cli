package candidatelease

import (
	"errors"
	"testing"
)

func TestProtocolRoundTripAndValidation(t *testing.T) {
	m := Message{Version: 1, Type: Adopt, Candidate: "candidate", LeaseGeneration: 4}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil || got.Version != m.Version || got.Type != m.Type || got.Candidate != m.Candidate || got.LeaseGeneration != m.LeaseGeneration {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := Parse([]byte(`{"version":1,"type":"candidate_adopt","candidate_id":"candidate"}`)); !errors.Is(err, ErrProtocol) {
		t.Fatal("missing generation accepted")
	}
	if _, err := (Message{Version: 1, Type: Release, Candidate: "candidate"}).Marshal(); !errors.Is(err, ErrProtocol) {
		t.Fatal("invalid release accepted")
	}
}

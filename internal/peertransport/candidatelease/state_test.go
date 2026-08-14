package candidatelease

import (
	"errors"
	"testing"
)

func TestLeaseStateAndGenerationFence(t *testing.T) {
	id, err := NewID([]byte("transcript"), "intent", 2, "relay_wss")
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(id, 9)
	if err != nil {
		t.Fatal(err)
	}
	if l.AttachAllowed(9) {
		t.Fatal("provisional lease attach")
	}
	if !errors.Is(l.Adopt(8), ErrFenced) {
		t.Fatal("old generation adopted")
	}
	if err := l.Adopt(9); err != nil {
		t.Fatal(err)
	}
	if err := l.Adopt(9); err != nil {
		t.Fatal(err)
	}
	if !l.AttachAllowed(9) {
		t.Fatal("retained lease attach")
	}
	if err := l.Release(9); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(9); err != nil {
		t.Fatal(err)
	}
	if l.AttachAllowed(9) || !errors.Is(l.Adopt(9), ErrFenced) {
		t.Fatal("closed lease reopened")
	}
}

func TestCandidateIDIsSharedAndSeparatesAttemptTuple(t *testing.T) {
	binding := []byte("authenticated-physical-binding")
	first, err := NewID(binding, "intent", 2, "relay_wss")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewID(binding, "intent", 2, "relay_wss")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same binding produced %q and %q", first, second)
	}
	for _, changed := range []struct {
		binding []byte
		intent  string
		attempt uint64
		path    string
	}{
		{[]byte("other-binding"), "intent", 2, "relay_wss"},
		{binding, "other-intent", 2, "relay_wss"},
		{binding, "intent", 3, "relay_wss"},
		{binding, "intent", 2, "relay_quic"},
	} {
		id, err := NewID(changed.binding, changed.intent, changed.attempt, changed.path)
		if err != nil {
			t.Fatal(err)
		}
		if id == first {
			t.Fatalf("tuple collision for %+v", changed)
		}
	}
}

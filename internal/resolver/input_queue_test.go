package resolver

import (
	"errors"
	"testing"
)

func TestTerminalInputQueueBoundsAndCompletion(t *testing.T) {
	queue := NewTerminalInputQueue(1)
	first, err := queue.Enqueue([]byte("one"))
	if err != nil || first != 1 {
		t.Fatalf("first=%d err=%v", first, err)
	}
	if _, err := queue.Enqueue([]byte("two")); !errors.Is(err, ErrTerminalInputQueueFull) {
		t.Fatalf("overflow err=%v", err)
	}
	queue.Complete(first, "accepted")
	second, err := queue.Enqueue([]byte("two"))
	if err != nil || second != 2 {
		t.Fatalf("second=%d err=%v", second, err)
	}
}

func TestTerminalInputQueueReconcileNeverGuessesDelivery(t *testing.T) {
	queue := NewTerminalInputQueue(4)
	first, _ := queue.Enqueue([]byte("one"))
	second, _ := queue.Enqueue([]byte("two"))
	uncertain := queue.Reconcile(first)
	if len(uncertain) != 1 || uncertain[0].Sequence != first {
		t.Fatalf("uncertain=%#v", uncertain)
	}
	if _, err := queue.Enqueue([]byte("three")); !errors.Is(err, ErrTerminalInputUncertain) {
		t.Fatalf("enqueue after uncertain err=%v", err)
	}
	if pending := queue.Pending(); len(pending) != 1 || pending[0].Sequence != second {
		t.Fatalf("pending=%#v", pending)
	}
}

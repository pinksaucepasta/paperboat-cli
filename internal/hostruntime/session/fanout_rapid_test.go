package session

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/history"
	"pgregory.net/rapid"
)

func TestFanoutRapidStateMachine(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(rapid.Uint8(), 1, 256).Draw(t, "operations")
		fanout := NewFanout()
		type attachment struct {
			attached bool
			evicted  bool
			maxBytes uint64
			queue    []history.Event
		}
		model := make(map[string]*attachment)
		var sequence uint64
		for index, operation := range operations {
			id := string([]byte{'a', 't', 't', '_', '0' + operation%8})
			state := model[id]
			switch operation % 4 {
			case 0:
				limit := uint64(operation/4%16 + 1)
				err := fanout.Attach(id, limit)
				if state != nil && state.attached {
					if err != ErrAttachmentExists {
						t.Fatalf("attach existing %q: %v", id, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("attach %q: %v", id, err)
				}
				model[id] = &attachment{attached: true, maxBytes: limit}
			case 1:
				err := fanout.Detach(id)
				if state == nil || !state.attached && !state.evicted {
					if err != ErrAttachmentUnknown {
						t.Fatalf("detach unknown %q: %v", id, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("detach %q: %v", id, err)
				}
				state.attached, state.evicted, state.queue = false, false, nil
			case 2:
				length := int(operation/4%8 + 1)
				payload := make([]byte, length)
				for offset := range payload {
					payload[offset] = byte(index + offset)
				}
				event := history.Event{Channel: 1, StartSequence: sequence, EndSequence: sequence + uint64(length), Data: payload}
				if _, err := fanout.Publish(event); err != nil {
					t.Fatalf("publish sequence %d: %v", sequence, err)
				}
				for _, candidate := range model {
					if !candidate.attached {
						continue
					}
					var queued uint64
					for _, item := range candidate.queue {
						queued += uint64(len(item.Data))
					}
					if uint64(length) > candidate.maxBytes-queued {
						candidate.attached, candidate.evicted, candidate.queue = false, true, nil
					} else {
						candidate.queue = append(candidate.queue, event)
					}
				}
				sequence += uint64(length)
			case 3:
				if state == nil || !state.attached {
					continue
				}
				got, ok, err := fanout.Next(id)
				if len(state.queue) == 0 {
					if err != nil || ok {
						t.Fatalf("empty next %q: event=%+v ok=%v err=%v", id, got, ok, err)
					}
					continue
				}
				want := state.queue[0]
				if err != nil || !ok || got.StartSequence != want.StartSequence || got.EndSequence != want.EndSequence || string(got.Data) != string(want.Data) {
					t.Fatalf("next %q: got=%+v ok=%v err=%v want=%+v", id, got, ok, err, want)
				}
				state.queue = state.queue[1:]
			}
		}
		want := 0
		for _, state := range model {
			if state.attached {
				want++
			}
		}
		if got := fanout.Count(); got != want {
			t.Fatalf("attached count=%d want=%d", got, want)
		}
	})
}

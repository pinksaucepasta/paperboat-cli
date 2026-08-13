package session

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/history"
)

func FuzzFanoutMatchesQueueModel(f *testing.F) {
	f.Add([]byte{0, 3, 1, 2, 0, 1, 2, 3, 1, 0, 2, 4, 3, 1, 0})
	f.Add([]byte{1, 1, 0, 0, 2, 7, 0, 3, 1, 1, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		fanout := NewFanout()
		type modelAttachment struct {
			attached bool
			evicted  bool
			maxBytes uint64
			queue    []history.Event
		}
		model := map[string]*modelAttachment{}
		sequence := uint64(0)
		for index, operation := range data {
			id := "att_" + string(rune('0'+operation%4))
			state := model[id]
			switch operation % 4 {
			case 0:
				maxBytes := uint64(operation/4%8 + 1)
				err := fanout.Attach(id, maxBytes)
				if state != nil && state.attached {
					if err != ErrAttachmentExists {
						t.Fatalf("attach existing %s: %v", id, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("attach %s: %v", id, err)
				}
				model[id] = &modelAttachment{attached: true, maxBytes: maxBytes}
			case 1:
				if state == nil || (!state.attached && !state.evicted) {
					if err := fanout.Detach(id); err != ErrAttachmentUnknown {
						t.Fatalf("detach unknown %s: %v", id, err)
					}
					continue
				}
				err := fanout.Detach(id)
				if err != nil {
					t.Fatalf("detach %s: %v", id, err)
				}
				state.attached, state.evicted, state.queue = false, false, nil
			case 2:
				length := int(operation/4%4 + 1)
				payload := make([]byte, length)
				for offset := range payload {
					payload[offset] = byte(index + offset)
				}
				event := history.Event{Channel: 1, StartSequence: sequence, EndSequence: sequence + uint64(length), Data: payload}
				evictions, err := fanout.Publish(event)
				if err != nil {
					t.Fatalf("publish sequence=%d: %v", sequence, err)
				}
				for _, candidate := range model {
					if !candidate.attached {
						continue
					}
					queued := uint64(0)
					for _, item := range candidate.queue {
						queued += uint64(len(item.Data))
					}
					if uint64(length) > candidate.maxBytes-queued {
						candidate.attached, candidate.evicted, candidate.queue = false, true, nil
					} else {
						candidate.queue = append(candidate.queue, event)
					}
				}
				if len(evictions) > len(model) {
					t.Fatalf("evictions=%d model=%d", len(evictions), len(model))
				}
				sequence += uint64(length)
			case 3:
				if state == nil || !state.attached {
					continue
				}
				got, ok, err := fanout.Next(id)
				if len(state.queue) == 0 {
					if err != nil || ok {
						t.Fatalf("empty next %s: event=%+v ok=%v err=%v", id, got, ok, err)
					}
					continue
				}
				want := state.queue[0]
				if err != nil || !ok || got.StartSequence != want.StartSequence || got.EndSequence != want.EndSequence || string(got.Data) != string(want.Data) {
					t.Fatalf("next %s: got=%+v ok=%v err=%v want=%+v", id, got, ok, err, want)
				}
				state.queue = state.queue[1:]
			}
		}
		wantCount := 0
		for _, state := range model {
			if state.attached {
				wantCount++
			}
		}
		if got := fanout.Count(); got != wantCount {
			t.Fatalf("attached count=%d want=%d", got, wantCount)
		}
	})
}

package hostdproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTripStrictMessages(t *testing.T) {
	lease := testLease(1)
	for _, message := range []Message{
		Hello{WorkerID: "runtime-2026.08.18.3", Version: "2026.08.18.3", APIMin: 1, APIMax: 2},
		Welcome{WorkerID: "runtime-2026.08.18.3", APIVersion: 2, Epoch: 4, Lease: lease},
		Ready{WorkerID: "runtime-2026.08.18.3", APIVersion: 2, Epoch: 4, Lease: lease},
		Activate{WorkerID: "runtime-2026.08.18.3", APIVersion: 2, Epoch: 4, Lease: lease},
		Heartbeat{WorkerID: "runtime-2026.08.18.3", APIVersion: 2, Epoch: 4, Lease: lease},
		Status{State: StateActive, WorkerID: "runtime-2026.08.18.3", APIVersion: 2, Epoch: 4},
		Status{State: StateEmpty},
		Error{Code: "fenced"},
	} {
		encoded, err := Encode(message)
		if err != nil {
			t.Fatalf("encode %T: %v", message, err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("decode %T: %v", message, err)
		}
		if got, want := string(decoded.messageType()), string(message.messageType()); got != want {
			t.Fatalf("type=%q want %q", got, want)
		}
	}
}

func TestDecodeRejectsUnknownOrAmbiguousJSON(t *testing.T) {
	lease := testLease(1)
	for _, frame := range [][]byte{
		[]byte(`{"schema":"paperboat.hostd-worker/v1","type":"hello","body":{"worker_id":"runtime","version":"1","api_min":1,"api_max":1},"unexpected":true}`),
		[]byte(`{"schema":"paperboat.hostd-worker/v1","type":"hello","body":{"worker_id":"runtime","version":"1","api_min":1,"api_max":1,"unexpected":true}}`),
		[]byte(`{"schema":"paperboat.hostd-worker/v1","type":"heartbeat","body":{"worker_id":"runtime","api_version":1,"epoch":1,"lease":"` + lease + `"}} {}`),
		[]byte(`{"schema":"paperboat.hostd-worker/v1","type":"execute","body":{}}`),
		[]byte(`{"schema":"wrong","type":"hello","body":{"worker_id":"runtime","version":"1","api_min":1,"api_max":1}}`),
	} {
		if _, err := Decode(frame); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("Decode(%s) error=%v, want ErrInvalidFrame", frame, err)
		}
	}
}

func TestStreamFramesAreBoundedAndSupportShortWrites(t *testing.T) {
	message := Hello{WorkerID: "runtime", Version: "2026.08.18.3", APIMin: 1, APIMax: 2}
	var wire shortWriter
	if err := WriteFrame(&wire, message); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.(*Hello); !ok {
		t.Fatalf("decoded %T, want *Hello", decoded)
	}

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], MaxFrameBytes+1)
	if _, err := ReadFrame(bytes.NewReader(prefix[:])); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversized frame error=%v, want ErrInvalidFrame", err)
	}
	binary.BigEndian.PutUint32(prefix[:], 10)
	if _, err := ReadFrame(bytes.NewReader(append(prefix[:], []byte(`{}`)...))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame error=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestControllerFencesSupersededWorkers(t *testing.T) {
	random := bytes.NewReader(append(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)...))
	controller, err := NewController(ControllerConfig{APIMin: 1, APIMax: 2, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.Negotiate(Hello{WorkerID: "runtime-old", Version: "2026.08.18.3", APIMin: 1, APIMax: 2})
	if err != nil || first.APIVersion != 2 || first.Epoch != 1 {
		t.Fatalf("first welcome=%+v err=%v", first, err)
	}
	if err := controller.MarkReady(readyFor(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(first)); err != nil {
		t.Fatal(err)
	}
	if err := controller.AcceptHeartbeat(heartbeatFor(first)); err != nil {
		t.Fatalf("first active heartbeat: %v", err)
	}

	second, err := controller.Negotiate(Hello{WorkerID: "runtime-new", Version: "2026.08.19.0", APIMin: 1, APIMax: 1})
	if err != nil || second.APIVersion != 1 || second.Epoch != 2 {
		t.Fatalf("second welcome=%+v err=%v", second, err)
	}
	// The active worker remains usable while its successor performs private
	// startup, then becomes fenced atomically at promotion.
	if err := controller.AcceptHeartbeat(heartbeatFor(first)); err != nil {
		t.Fatalf("old worker fenced before promotion: %v", err)
	}
	if err := controller.MarkReady(readyFor(second)); err != nil {
		t.Fatal(err)
	}
	status, err := controller.Activate(activateFor(second))
	if err != nil || status.State != StateActive || status.WorkerID != "runtime-new" || status.Epoch != 2 {
		t.Fatalf("activation status=%+v err=%v", status, err)
	}
	if err := controller.AcceptHeartbeat(heartbeatFor(first)); !errors.Is(err, ErrFenced) {
		t.Fatalf("old heartbeat error=%v, want ErrFenced", err)
	}
	if err := controller.AcceptHeartbeat(heartbeatFor(second)); err != nil {
		t.Fatalf("new heartbeat: %v", err)
	}
}

func TestControllerHandleAcceptsOnlyLifecycleMessages(t *testing.T) {
	controller, err := NewController(ControllerConfig{APIMin: 1, APIMax: 1, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handle(&Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1})
	if err != nil {
		t.Fatal(err)
	}
	welcome, ok := response.(Welcome)
	if !ok {
		t.Fatalf("hello response=%T, want Welcome", response)
	}
	if _, err := controller.Handle(readyFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handle(activateFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if response, err = controller.Handle(heartbeatFor(welcome)); err != nil {
		t.Fatal(err)
	} else if status, ok := response.(Status); !ok || status.State != StateActive {
		t.Fatalf("heartbeat response=%+v", response)
	}
	if response, err = controller.Handle(Status{State: StateEmpty}); err != nil {
		t.Fatalf("status request error=%v", err)
	} else if status, ok := response.(Status); !ok || status.State != StateActive {
		t.Fatalf("status response=%+v", response)
	}
}

func TestControllerRejectsUnreadyStaleAndIncompatibleCandidates(t *testing.T) {
	random := bytes.NewReader(append(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)...))
	controller, err := NewController(ControllerConfig{APIMin: 2, APIMax: 3, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Negotiate(Hello{WorkerID: "runtime-old", Version: "1", APIMin: 1, APIMax: 1}); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("incompatible error=%v, want ErrIncompatible", err)
	}
	first, err := controller.Negotiate(Hello{WorkerID: "runtime-a", Version: "1", APIMin: 2, APIMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(first)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unready activate error=%v, want ErrNotReady", err)
	}
	second, err := controller.Negotiate(Hello{WorkerID: "runtime-b", Version: "1", APIMin: 2, APIMax: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.MarkReady(readyFor(first)); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale ready error=%v, want ErrFenced", err)
	}
	if err := controller.MarkReady(readyFor(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(Activate{WorkerID: second.WorkerID, APIVersion: second.APIVersion, Epoch: second.Epoch, Lease: testLease(9)}); !errors.Is(err, ErrFenced) {
		t.Fatalf("forged activate error=%v, want ErrFenced", err)
	}
}

func TestControllerReturnsActiveFenceForEmptyStatusQuery(t *testing.T) {
	controller, err := NewController(ControllerConfig{APIMin: 1, APIMax: 1, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	welcome, err := controller.Negotiate(Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.MarkReady(readyFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(welcome)); err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handle(Status{State: StateEmpty})
	if err != nil {
		t.Fatal(err)
	}
	status, ok := response.(Status)
	if !ok || status.State != StateActive || status.Epoch != welcome.Epoch {
		t.Fatalf("response=%+v", response)
	}
}

func TestActiveStatusRecordsOnlyAcceptedHeartbeat(t *testing.T) {
	now := time.Date(2026, 8, 18, 2, 3, 4, 0, time.UTC)
	controller, err := NewController(ControllerConfig{APIMin: 1, APIMax: 1, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 32)), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	welcome, err := controller.Negotiate(Hello{WorkerID: "runtime", Version: "1", APIMin: 1, APIMax: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.MarkReady(readyFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if status := controller.Status(); status.LastHeartbeatUnixMilli != 0 {
		t.Fatalf("activation heartbeat=%d", status.LastHeartbeatUnixMilli)
	}
	if err := controller.AcceptHeartbeat(heartbeatFor(welcome)); err != nil {
		t.Fatal(err)
	}
	if status := controller.Status(); status.LastHeartbeatUnixMilli != now.UnixMilli() {
		t.Fatalf("heartbeat=%d", status.LastHeartbeatUnixMilli)
	}
}

func TestControllerRejectsEpochWrapAndRepeatedLease(t *testing.T) {
	leaseBytes := bytes.Repeat([]byte{7}, 32)
	controller, err := NewController(ControllerConfig{APIMin: 1, APIMax: 1, Random: bytes.NewReader(bytes.Repeat(leaseBytes, 5))})
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.Negotiate(Hello{WorkerID: "runtime-a", Version: "1", APIMin: 1, APIMax: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.MarkReady(readyFor(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Activate(activateFor(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Negotiate(Hello{WorkerID: "runtime-b", Version: "1", APIMin: 1, APIMax: 1}); !errors.Is(err, ErrLeaseGeneration) {
		t.Fatalf("repeated lease error=%v, want ErrLeaseGeneration", err)
	}
	controller.active.epoch = ^uint64(0)
	if _, err := controller.Negotiate(Hello{WorkerID: "runtime-c", Version: "1", APIMin: 1, APIMax: 1}); !errors.Is(err, ErrEpochExhausted) {
		t.Fatalf("epoch wrap error=%v, want ErrEpochExhausted", err)
	}
}

func readyFor(value Welcome) Ready {
	return Ready(value)
}

func activateFor(value Welcome) Activate {
	return Activate(value)
}

func heartbeatFor(value Welcome) Heartbeat {
	return Heartbeat(value)
}

func testLease(byteValue byte) string {
	return "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) > 2 {
		data = data[:2]
	}
	return w.Buffer.Write(data)
}

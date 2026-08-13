package resumablestream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func testIdentity() StreamIdentity {
	return StreamIdentity{Principal: "endpoint_cli", OperationID: "operation_1", Consumer: "ssh", StreamID: "0123456789abcdef0123456789abcdef"}
}

func testPair(t *testing.T, window int) (*Conn, *Conn) {
	t.Helper()
	left, err := New(t.Context(), Config{WindowBytes: window, Role: RoleInitiator, Identity: testIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(t.Context(), Config{WindowBytes: window, Role: RoleResponder, Identity: testIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}

func attachInitial(t *testing.T, initiator, responder *Conn) (net.Conn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	accepted := make(chan error, 1)
	go func() { accepted <- responder.AcceptCarrier(t.Context(), right) }()
	if err := initiator.AttachInitial(t.Context(), left); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	return left, right
}

func prepare(t *testing.T, initiator, responder *Conn) (CarrierHandle, net.Conn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	accepted := make(chan error, 1)
	go func() { accepted <- responder.AcceptCarrier(t.Context(), right) }()
	handle, err := initiator.PrepareCarrier(t.Context(), left)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	return handle, left, right
}

func TestNewRequiresRoleAndIdentity(t *testing.T) {
	valid := Config{WindowBytes: 64 << 10, Role: RoleInitiator, Identity: testIdentity()}
	for name, mutate := range map[string]func(*Config){
		"role":      func(c *Config) { c.Role = RoleUnspecified },
		"principal": func(c *Config) { c.Identity.Principal = "" },
		"operation": func(c *Config) { c.Identity.OperationID = "" },
		"consumer":  func(c *Config) { c.Identity.Consumer = "" },
		"stream":    func(c *Config) { c.Identity.StreamID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if _, err := New(t.Context(), value); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestInitialAttachOpaqueBytesAndHalfClose(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	payload := []byte{0, 1, 2, 0xff, 0, 0x80, 3}
	if n, err := left.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write=%d err=%v", n, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%x", got)
	}
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF=%v", err)
	}
}

func TestPreparedCarrierCarriesNoApplicationDataUntilCommit(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	handle, _, _ := prepare(t, left, right)
	payload := []byte("still-primary")
	if _, err := left.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q", got)
	}
	if err := left.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	payload = []byte("new-active")
	if _, err := left.Write(payload); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(payload))
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q", got)
	}
}

func TestDiscardPreparedAllowsNewerProposalWithoutDisturbingActive(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	first, _, _ := prepare(t, left, right)
	if err := left.DropPrepared(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	second, _, _ := prepare(t, left, right)
	if second.Epoch != first.Epoch+1 {
		t.Fatalf("second epoch=%d want=%d", second.Epoch, first.Epoch+1)
	}
	if err := left.PromoteCarrier(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	payload := []byte("active-after-discard")
	if _, err := left.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q", got)
	}
}

func TestResponderSupersedesAbandonedLowerEpochPreparedCarrier(t *testing.T) {
	initiator, responder := testPair(t, 64<<10)
	attachInitial(t, initiator, responder)
	oldLeft, oldRight := net.Pipe()
	oldID, err := randomCarrierID()
	if err != nil {
		t.Fatal(err)
	}
	initiator.mu.Lock()
	oldEpoch := initiator.nextEpoch + 1
	digest, committed, ack := initiator.identity, initiator.committedEpoch, initiator.recvBase
	initiator.mu.Unlock()
	oldAccepted := make(chan error, 1)
	go func() { oldAccepted <- responder.AcceptCarrier(t.Context(), oldRight) }()
	if err := writeHello(oldLeft, helloV2{kind: helloPrepare, digest: digest, carrier: oldID, epoch: oldEpoch, committedEpoch: committed, ack: ack}); err != nil {
		t.Fatal(err)
	}
	if _, err := readHello(oldLeft); err != nil {
		t.Fatal(err)
	}
	if err := <-oldAccepted; err != nil {
		t.Fatal(err)
	}

	newLeft, newRight := net.Pipe()
	newID, err := randomCarrierID()
	if err != nil {
		t.Fatal(err)
	}
	newAccepted := make(chan error, 1)
	go func() { newAccepted <- responder.AcceptCarrier(t.Context(), newRight) }()
	if err := writeHello(newLeft, helloV2{kind: helloPrepare, digest: digest, carrier: newID, epoch: oldEpoch + 1, committedEpoch: committed, ack: ack}); err != nil {
		t.Fatal(err)
	}
	ready, err := readHello(newLeft)
	if err != nil || ready.kind != helloReady || ready.carrier != newID || ready.epoch != oldEpoch+1 {
		t.Fatalf("ready=%+v err=%v", ready, err)
	}
	if err := <-newAccepted; err != nil {
		t.Fatal(err)
	}
	responder.mu.Lock()
	prepared := responder.prepared
	responder.mu.Unlock()
	if prepared == nil || prepared.id != newID || prepared.epoch != oldEpoch+1 || prepared.state != carrierPrepared {
		t.Fatalf("prepared=%+v", prepared)
	}
	// Frames already queued by the superseded carrier are carrier-local. They
	// cannot mutate or terminate the logical stream after supersession.
	_ = initiator.writeFrame(&physicalCarrier{conn: oldLeft}, frameCommit, oldEpoch, nil)
	_ = oldLeft.Close()
	select {
	case <-responder.Done():
		t.Fatal("late superseded COMMIT aborted the logical stream")
	case <-time.After(10 * time.Millisecond):
	}
	_ = newLeft.Close()
}

type failReadyConn struct{ net.Conn }

func (c *failReadyConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestResponderReadyFailureRollsBackExactProvisionalCarrier(t *testing.T) {
	initiator, responder := testPair(t, 64<<10)
	attachInitial(t, initiator, responder)
	left, right := net.Pipe()
	id, err := randomCarrierID()
	if err != nil {
		t.Fatal(err)
	}
	initiator.mu.Lock()
	epoch := initiator.nextEpoch + 1
	request := helloV2{kind: helloPrepare, digest: initiator.identity, carrier: id, epoch: epoch, committedEpoch: initiator.committedEpoch, ack: initiator.recvBase}
	initiator.mu.Unlock()
	accepted := make(chan error, 1)
	go func() { accepted <- responder.AcceptCarrier(t.Context(), &failReadyConn{Conn: right}) }()
	if err := writeHello(left, request); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err == nil {
		t.Fatal("READY write failure was accepted")
	}
	responder.mu.Lock()
	prepared := responder.prepared
	responder.mu.Unlock()
	if prepared != nil {
		t.Fatalf("failed provisional carrier retained: %+v", prepared)
	}

	nextLeft, nextRight := net.Pipe()
	nextID, err := randomCarrierID()
	if err != nil {
		t.Fatal(err)
	}
	nextAccepted := make(chan error, 1)
	go func() { nextAccepted <- responder.AcceptCarrier(t.Context(), nextRight) }()
	request.carrier, request.epoch = nextID, epoch+1
	if err := writeHello(nextLeft, request); err != nil {
		t.Fatal(err)
	}
	if _, err := readHello(nextLeft); err != nil {
		t.Fatal(err)
	}
	if err := <-nextAccepted; err != nil {
		t.Fatal(err)
	}
	_ = nextLeft.Close()
}

func TestResponderRejectsStalePrepareWithoutMutation(t *testing.T) {
	initiator, responder := testPair(t, 64<<10)
	attachInitial(t, initiator, responder)
	responder.mu.Lock()
	beforePrepared, committed, next := responder.prepared, responder.committedEpoch, responder.nextEpoch
	responder.mu.Unlock()
	for name, request := range map[string]helloV2{
		"older committed base": {kind: helloPrepare, digest: responder.identity, epoch: next + 1, committedEpoch: committed - 1},
		"committed epoch":      {kind: helloPrepare, digest: responder.identity, epoch: committed, committedEpoch: committed},
		"already allocated":    {kind: helloPrepare, digest: responder.identity, epoch: next, committedEpoch: committed},
	} {
		t.Run(name, func(t *testing.T) {
			request.carrier, _ = randomCarrierID()
			left, right := net.Pipe()
			accepted := make(chan error, 1)
			go func() { accepted <- responder.AcceptCarrier(t.Context(), right) }()
			if err := writeHello(left, request); err != nil {
				t.Fatal(err)
			}
			_ = left.Close()
			if err := <-accepted; !errors.Is(err, ErrProtocol) {
				t.Fatalf("error=%v", err)
			}
			responder.mu.Lock()
			prepared, gotCommitted, gotNext := responder.prepared, responder.committedEpoch, responder.nextEpoch
			responder.mu.Unlock()
			if prepared != beforePrepared || gotCommitted != committed || gotNext != next {
				t.Fatalf("state mutated prepared=%p committed=%d next=%d", prepared, gotCommitted, gotNext)
			}
		})
	}
}

func TestActiveFailureEmitsDetachedWithoutPromotingPrepared(t *testing.T) {
	left, right := testPair(t, 64<<10)
	primaryLeft, primaryRight := attachInitial(t, left, right)
	handle, _, _ := prepare(t, left, right)
	_ = primaryLeft.Close()
	_ = primaryRight.Close()
	select {
	case event := <-left.Events():
		for event.Type != EventDetached {
			select {
			case event = <-left.Events():
			case <-time.After(time.Second):
				t.Fatal("no detached event")
			}
		}
		if event.PreparedCarrier != handle.ID {
			t.Fatalf("prepared=%x want=%x", event.PreparedCarrier, handle.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	if err := left.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
}

func TestDetachedRecoveryTimeoutAbortsLogicalStream(t *testing.T) {
	identity := testIdentity()
	left, err := New(t.Context(), Config{WindowBytes: 64 << 10, Role: RoleInitiator, Identity: identity, DetachedTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(t.Context(), Config{WindowBytes: 64 << 10, Role: RoleResponder, Identity: identity, DetachedTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	primaryLeft, primaryRight := attachInitial(t, left, right)
	_ = primaryLeft.Close()
	_ = primaryRight.Close()
	for _, stream := range []*Conn{left, right} {
		select {
		case <-stream.Done():
		case <-time.After(time.Second):
			t.Fatal("detached stream did not abort")
		}
	}
}

func TestRoutingIdentityMismatchRejectedBeforeAttach(t *testing.T) {
	identity := testIdentity()
	left, err := New(t.Context(), Config{WindowBytes: 64 << 10, Role: RoleInitiator, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	identity.Principal = "other_endpoint"
	right, err := New(t.Context(), Config{WindowBytes: 64 << 10, Role: RoleResponder, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	a, b := net.Pipe()
	accepted := make(chan error, 1)
	go func() { accepted <- right.AcceptCarrier(t.Context(), b) }()
	if err := left.AttachInitial(t.Context(), a); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	if err := <-accepted; !errors.Is(err, ErrProtocol) {
		t.Fatalf("responder error=%v", err)
	}
}

func TestCarrierIDsAreIndependentFromEpochs(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	h1, _, _ := prepare(t, left, right)
	if h1.ID == (CarrierID{}) || h1.Epoch != 2 {
		t.Fatalf("first=%+v", h1)
	}
	if err := left.PromoteCarrier(t.Context(), h1); err != nil {
		t.Fatal(err)
	}
	h2, _, _ := prepare(t, left, right)
	if h2.ID == h1.ID || h2.Epoch != 3 {
		t.Fatalf("first=%+v second=%+v", h1, h2)
	}
}

func TestStaleCarrierHandleCannotReplaceActive(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	handle, _, _ := prepare(t, left, right)
	if err := left.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	if err := left.PromoteCarrier(t.Context(), handle); !errors.Is(err, ErrProtocol) {
		t.Fatalf("stale promote=%v", err)
	}
}

func TestRetainedApplicationFrameDispositionSurvivesConfirmRetirement(t *testing.T) {
	stream, _ := testPair(t, 64<<10)
	carrier := &physicalCarrier{state: carrierRetained, epoch: 2}
	stream.mu.Lock()
	stream.retained = carrier
	stream.committedEpoch = 3
	stream.mu.Unlock()
	if got := stream.applicationDisposition(carrier); got != applicationAccept {
		t.Fatalf("retained disposition=%d want accept", got)
	}
	stream.mu.Lock()
	stream.retained = nil
	stream.mu.Unlock()
	if got := stream.applicationDisposition(carrier); got != applicationIgnoreLate {
		t.Fatalf("retired disposition=%d want ignore late", got)
	}
}

func TestFINDuringPromotionRemainsLogicalStreamState(t *testing.T) {
	left, right := testPair(t, 64<<10)
	attachInitial(t, left, right)
	handle, _, _ := prepare(t, left, right)
	if _, err := left.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := left.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(right)
	if err != nil || string(got) != "final" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestConcurrentFullDuplexAcrossPromotion(t *testing.T) {
	left, right := testPair(t, maximumFrame*4)
	attachInitial(t, left, right)
	handle, _, _ := prepare(t, left, right)
	a := bytes.Repeat([]byte("left"), maximumFrame)
	b := bytes.Repeat([]byte("right"), maximumFrame)
	errs := make(chan error, 4)
	go func() { _, err := left.Write(a); errs <- err }()
	go func() { _, err := right.Write(b); errs <- err }()
	leftGot := make([]byte, len(b))
	rightGot := make([]byte, len(a))
	go func() { _, err := io.ReadFull(left, leftGot); errs <- err }()
	go func() { _, err := io.ReadFull(right, rightGot); errs <- err }()
	if err := left.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(leftGot, b) || !bytes.Equal(rightGot, a) {
		t.Fatal("full-duplex bytes changed")
	}
}

func TestBackpressureAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	identity := testIdentity()
	left, err := New(ctx, Config{WindowBytes: maximumFrame, Role: RoleInitiator, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(ctx, Config{WindowBytes: maximumFrame, Role: RoleResponder, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	attachInitial(t, left, right)
	done := make(chan error, 1)
	go func() { _, err := left.Write(bytes.Repeat([]byte{1}, maximumFrame*3)); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write did not cancel")
	}
}

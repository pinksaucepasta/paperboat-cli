package relaynoise

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/flynn/noise"
)

func TestRekeyMarkerRoundTripAndBinding(t *testing.T) {
	var binding [32]byte
	copy(binding[:], bytes.Repeat([]byte{7}, 32))
	marker := RekeyMarker{Generation: 4, Direction: RekeyInitiatorToResponder, Kind: RekeyCommit, Binding: binding}
	encoded, err := marker.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRekeyMarker(encoded, binding, RekeyInitiatorToResponder, RekeyCommit, 3)
	if err != nil || got != marker {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	wrong := binding
	wrong[0]++
	if _, err := ParseRekeyMarker(encoded, wrong, RekeyInitiatorToResponder, RekeyCommit, 3); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("wrong binding err=%v", err)
	}
}

func TestRekeyHandshakeControlRoundTripAndLimits(t *testing.T) {
	var binding [32]byte
	binding[0] = 4
	control := RekeyHandshakeControl{Kind: RekeyHandshakeRequest, Generation: 3, Binding: binding, Message: []byte("fresh-ik")}
	encoded, err := control.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRekeyHandshakeControl(encoded, RekeyHandshakeRequest, 3, binding)
	if err != nil || got.Kind != control.Kind || got.Generation != control.Generation || got.Binding != binding || !bytes.Equal(got.Message, control.Message) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := ParseRekeyHandshakeControl(encoded, RekeyHandshakeResponse, 3, binding); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("wrong kind err=%v", err)
	}
	control.Message = make([]byte, maximumPlaintext)
	if _, err := control.MarshalBinary(); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("oversized control err=%v", err)
	}
}

func TestRekeyMarkerRejectsReplayDirectionAndGeneration(t *testing.T) {
	var binding [32]byte
	binding[0] = 1
	marker := RekeyMarker{Generation: 2, Direction: RekeyResponderToInitiator, Kind: RekeyAcknowledgement, Binding: binding}
	encoded, _ := marker.MarshalBinary()
	for _, test := range []struct {
		name      string
		direction RekeyDirection
		kind      RekeyMarkerKind
		minimum   uint64
	}{{"direction", RekeyInitiatorToResponder, RekeyAcknowledgement, 1}, {"kind", RekeyResponderToInitiator, RekeyCommit, 1}, {"replay", RekeyResponderToInitiator, RekeyAcknowledgement, 3}} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseRekeyMarker(encoded, binding, test.direction, test.kind, test.minimum); !errors.Is(err, ErrRekeyMarker) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestRekeyMarkerIsOpaqueInsideNoiseRecord(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	binding := initiatorSession.ChannelBinding()
	marker := RekeyMarker{Generation: 2, Direction: RekeyInitiatorToResponder, Kind: RekeyCommit, Binding: binding}
	payload, err := marker.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	record, err := initiatorSession.Seal(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, payload) || bytes.Contains(record, binding[:]) {
		t.Fatal("rekey marker visible outside Noise ciphertext")
	}
	opened, _, err := responderSession.Open(record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRekeyMarker(opened, binding, RekeyInitiatorToResponder, RekeyCommit, 2)
	if err != nil || got != marker {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRekeyExchangeRequiresOrderedDirectionalCommitAndAcknowledgement(t *testing.T) {
	var binding [32]byte
	binding[0] = 9
	exchange, err := NewRekeyExchange(binding, 3)
	if err != nil {
		t.Fatal(err)
	}
	marker := func(direction RekeyDirection, kind RekeyMarkerKind) RekeyMarker {
		return RekeyMarker{Generation: 3, Direction: direction, Kind: kind, Binding: binding}
	}
	if _, err := exchange.Accept(marker(RekeyInitiatorToResponder, RekeyAcknowledgement)); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("early acknowledgement err=%v", err)
	}
	if complete, err := exchange.Accept(marker(RekeyInitiatorToResponder, RekeyCommit)); err != nil || complete {
		t.Fatalf("first commit complete=%v err=%v", complete, err)
	}
	if _, err := exchange.Accept(marker(RekeyInitiatorToResponder, RekeyCommit)); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("duplicate commit err=%v", err)
	}
	if complete, err := exchange.Accept(marker(RekeyInitiatorToResponder, RekeyAcknowledgement)); err != nil || complete {
		t.Fatalf("first acknowledgement complete=%v err=%v", complete, err)
	}
	if complete, err := exchange.Accept(marker(RekeyResponderToInitiator, RekeyCommit)); err != nil || complete {
		t.Fatalf("second commit complete=%v err=%v", complete, err)
	}
	if complete, err := exchange.Accept(marker(RekeyResponderToInitiator, RekeyAcknowledgement)); err != nil || !complete {
		t.Fatalf("second acknowledgement complete=%v err=%v", complete, err)
	}
	if _, err := exchange.Accept(marker(RekeyResponderToInitiator, RekeyAcknowledgement)); !errors.Is(err, ErrRekeyMarker) {
		t.Fatalf("duplicate acknowledgement err=%v", err)
	}
}

func TestFreshIKRekeyBindsPriorChannelAndGeneration(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	previousInitiator, previousResponder := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	prior := previousResponder.ChannelBinding()
	i, err := NewRekeyInitiator(initiatorKey, key32(responderKey.Public), prologue, handle, prior, 2)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRekeyResponder(responderKey, key32(initiatorKey.Public), prologue, handle, prior, 2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := i.WriteRequest([]byte("rekey-request"))
	if err != nil {
		t.Fatal(err)
	}
	requestControl, _ := (RekeyHandshakeControl{Kind: RekeyHandshakeRequest, Generation: 2, Binding: prior, Message: request}).MarshalBinary()
	requestRecord, err := previousInitiator.Seal(requestControl, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(requestRecord, request) || bytes.Contains(requestRecord, prior[:]) {
		t.Fatal("fresh IK request visible outside old Noise state")
	}
	openedRequest, _, err := previousResponder.Open(requestRecord)
	if err != nil {
		t.Fatal(err)
	}
	parsedRequest, err := ParseRekeyHandshakeControl(openedRequest, RekeyHandshakeRequest, 2, prior)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := r.ReadRequest(parsedRequest.Message); err != nil || string(payload) != "rekey-request" {
		t.Fatalf("request=%q err=%v", payload, err)
	}
	response, responderSession, err := r.WriteResponse([]byte("rekey-response"))
	if err != nil {
		t.Fatal(err)
	}
	responseControl, _ := (RekeyHandshakeControl{Kind: RekeyHandshakeResponse, Generation: 2, Binding: prior, Message: response}).MarshalBinary()
	responseRecord, err := previousResponder.Seal(responseControl, false)
	if err != nil {
		t.Fatal(err)
	}
	openedResponse, _, err := previousInitiator.Open(responseRecord)
	if err != nil {
		t.Fatal(err)
	}
	parsedResponse, err := ParseRekeyHandshakeControl(openedResponse, RekeyHandshakeResponse, 2, prior)
	if err != nil {
		t.Fatal(err)
	}
	payload, initiatorSession, err := i.ReadResponse(parsedResponse.Message)
	if err != nil || string(payload) != "rekey-response" {
		t.Fatalf("response=%q err=%v", payload, err)
	}
	if initiatorSession.ChannelBinding() != responderSession.ChannelBinding() || initiatorSession.ChannelBinding() == prior {
		t.Fatal("fresh IK did not derive a new shared binding")
	}
}

func TestFreshIKRekeyRejectsPriorBindingOrGenerationMismatch(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	_, previousResponder := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	prior := previousResponder.ChannelBinding()
	for name, mutate := range map[string]func(*[32]byte, *uint64){
		"binding":    func(binding *[32]byte, _ *uint64) { binding[0] ^= 1 },
		"generation": func(_ *[32]byte, generation *uint64) { *generation = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			responderBinding, generation := prior, uint64(2)
			mutate(&responderBinding, &generation)
			i, _ := NewRekeyInitiator(initiatorKey, key32(responderKey.Public), prologue, handle, prior, 2)
			r, _ := NewRekeyResponder(responderKey, key32(initiatorKey.Public), prologue, handle, responderBinding, generation)
			request, _ := i.WriteRequest(nil)
			if _, err := r.ReadRequest(request); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestRekeyTransitionSwitchesDirectionsWithoutPausingTraffic(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, responderSession := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	prior := initiatorSession.ChannelBinding()
	nextInitiator, nextResponder := rekeySessionsForIdentities(t, initiatorKey, responderKey, handle, prologue, prior, 2)
	newBinding := nextInitiator.ChannelBinding()
	initiatorTransition, err := NewRekeyTransition(initiatorSession, nextInitiator, 2)
	if err != nil {
		t.Fatal(err)
	}
	responderTransition, err := NewRekeyTransition(responderSession, nextResponder, 2)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(sender, receiver *Session, senderTransition, receiverTransition *RekeyTransition, marker RekeyMarker) bool {
		payload, _ := marker.MarshalBinary()
		record, err := sender.Seal(payload, false)
		if err != nil {
			t.Fatal(err)
		}
		opened, _, err := receiver.Open(record)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRekeyMarker(opened, prior, marker.Direction, marker.Kind, 2)
		if err != nil {
			t.Fatal(err)
		}
		localComplete, err := senderTransition.Accept(marker)
		if err != nil {
			t.Fatal(err)
		}
		remoteComplete, err := receiverTransition.Accept(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if localComplete != remoteComplete {
			t.Fatal("transition completion diverged")
		}
		return localComplete
	}
	marker := func(direction RekeyDirection, kind RekeyMarkerKind) RekeyMarker {
		return RekeyMarker{Generation: 2, Direction: direction, Kind: kind, Binding: prior}
	}
	if deliver(initiatorSession, responderSession, initiatorTransition, responderTransition, marker(RekeyInitiatorToResponder, RekeyCommit)) {
		t.Fatal("completed at first commit")
	}
	if deliver(responderSession, initiatorSession, responderTransition, initiatorTransition, marker(RekeyInitiatorToResponder, RekeyAcknowledgement)) {
		t.Fatal("completed after one direction")
	}
	newRecord, err := initiatorSession.Seal([]byte("new-i2r"), false)
	if err != nil || binary.BigEndian.Uint64(newRecord[18:26]) != 0 {
		t.Fatalf("new direction sequence err=%v", err)
	}
	if opened, _, err := responderSession.Open(newRecord); err != nil || string(opened) != "new-i2r" {
		t.Fatalf("new i2r=%q err=%v", opened, err)
	}
	oldReverseRecord, err := responderSession.Seal([]byte("old-r2i-still-live"), false)
	if err != nil {
		t.Fatal(err)
	}
	if opened, _, err := initiatorSession.Open(oldReverseRecord); err != nil || string(opened) != "old-r2i-still-live" {
		t.Fatalf("old reverse traffic=%q err=%v", opened, err)
	}
	if deliver(responderSession, initiatorSession, responderTransition, initiatorTransition, marker(RekeyResponderToInitiator, RekeyCommit)) {
		t.Fatal("completed at second commit")
	}
	if !deliver(initiatorSession, responderSession, initiatorTransition, responderTransition, marker(RekeyResponderToInitiator, RekeyAcknowledgement)) {
		t.Fatal("did not complete after both acknowledgements")
	}
	if initiatorSession.ChannelBinding() != newBinding || responderSession.ChannelBinding() != newBinding || newBinding == prior {
		t.Fatal("final channel binding mismatch")
	}
	newRecord, err = responderSession.Seal([]byte("new-r2i"), false)
	if err != nil || binary.BigEndian.Uint64(newRecord[18:26]) != 0 {
		t.Fatalf("new reverse direction sequence err=%v", err)
	}
	if opened, _, err := initiatorSession.Open(newRecord); err != nil || string(opened) != "new-r2i" {
		t.Fatalf("new r2i=%q err=%v", opened, err)
	}
}

func sessionsForIdentities(t *testing.T, initiatorKey, responderKey noise.DHKey, handle [16]byte, prologue Prologue) (*Session, *Session) {
	t.Helper()
	i, _ := NewInitiator(initiatorKey, key32(responderKey.Public), prologue, handle)
	r, _ := NewResponder(responderKey, key32(initiatorKey.Public), prologue, handle)
	request, _ := i.WriteRequest(nil)
	if _, err := r.ReadRequest(request); err != nil {
		t.Fatal(err)
	}
	response, responderSession, err := r.WriteResponse(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, initiatorSession, err := i.ReadResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return initiatorSession, responderSession
}

func rekeySessionsForIdentities(t *testing.T, initiatorKey, responderKey noise.DHKey, handle [16]byte, prologue Prologue, prior [32]byte, generation uint64) (*Session, *Session) {
	t.Helper()
	i, _ := NewRekeyInitiator(initiatorKey, key32(responderKey.Public), prologue, handle, prior, generation)
	r, _ := NewRekeyResponder(responderKey, key32(initiatorKey.Public), prologue, handle, prior, generation)
	request, _ := i.WriteRequest(nil)
	if _, err := r.ReadRequest(request); err != nil {
		t.Fatal(err)
	}
	response, responderSession, err := r.WriteResponse(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, initiatorSession, err := i.ReadResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	return initiatorSession, responderSession
}

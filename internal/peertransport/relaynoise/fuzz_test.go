package relaynoise

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

func FuzzResponderReadRequest(f *testing.F) {
	initiatorKey, responderKey, handle, prologue := fuzzIdentities(f)
	initiator, err := NewInitiator(initiatorKey, key32(responderKey.Public), prologue, handle)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := initiator.WriteRequest([]byte("private-request"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add(make([]byte, 65536))

	f.Fuzz(func(t *testing.T, message []byte) {
		responder, err := NewResponder(responderKey, key32(initiatorKey.Public), prologue, handle)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := responder.ReadRequest(message)
		if err != nil {
			return
		}
		if len(payload) > 65535-96 {
			t.Fatal("accepted IK request payload exceeds protocol limit")
		}
		if _, _, err := responder.WriteResponse(nil); err != nil {
			t.Fatalf("accepted IK request cannot complete: %v", err)
		}
	})
}

func FuzzSessionOpen(f *testing.F) {
	initiatorKey, responderKey, handle, prologue := fuzzIdentities(f)
	f.Add([]byte(nil))
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, mutation []byte) {
		initiator, responder := fuzzSessions(t, initiatorKey, responderKey, handle, prologue)
		plaintext := []byte("private-record")
		record, err := initiator.Seal(plaintext, false)
		if err != nil {
			t.Fatal(err)
		}
		candidate := mutateRecord(record, mutation)
		opened, closed, err := responder.Open(candidate)
		if err != nil {
			return
		}
		if closed || !bytes.Equal(opened, plaintext) {
			t.Fatal("accepted record changed authenticated contents")
		}
	})
}

func FuzzParseRekeyHandshakeControl(f *testing.F) {
	var binding [32]byte
	binding[0] = 1
	valid, err := (RekeyHandshakeControl{Kind: RekeyHandshakeRequest, Generation: 2, Binding: binding, Message: []byte("fresh-ik")}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte("PBRH"))

	f.Fuzz(func(t *testing.T, value []byte) {
		control, err := ParseRekeyHandshakeControl(value, RekeyHandshakeRequest, 2, binding)
		if err != nil {
			return
		}
		canonical, err := control.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted rekey handshake cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, value) {
			t.Fatal("accepted rekey handshake is not canonical")
		}
	})
}

func FuzzParseRekeyMarker(f *testing.F) {
	var binding [32]byte
	binding[0] = 1
	valid, err := (RekeyMarker{Generation: 2, Direction: RekeyInitiatorToResponder, Kind: RekeyCommit, Binding: binding}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte("PBRK"))

	f.Fuzz(func(t *testing.T, value []byte) {
		marker, err := ParseRekeyMarker(value, binding, RekeyInitiatorToResponder, RekeyCommit, 2)
		if err != nil {
			return
		}
		canonical, err := marker.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted rekey marker cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, value) {
			t.Fatal("accepted rekey marker is not canonical")
		}
	})
}

func mutateRecord(record, mutation []byte) []byte {
	if len(mutation) == 0 {
		return record
	}
	switch mutation[0] % 4 {
	case 0:
		return append([]byte(nil), mutation[1:]...)
	case 1:
		return record[:int(mutation[0])%len(record)]
	case 2:
		candidate := append([]byte(nil), record...)
		for index, value := range mutation[1:] {
			candidate[index%len(candidate)] ^= value
		}
		return candidate
	default:
		return append(append([]byte(nil), record...), mutation[1:]...)
	}
}

func fuzzIdentities(tb testing.TB) (initiator, responder noise.DHKey, handle [16]byte, prologue Prologue) {
	tb.Helper()
	var err error
	initiator, err = GenerateStaticKey()
	if err != nil {
		tb.Fatal(err)
	}
	responder, err = GenerateStaticKey()
	if err != nil {
		tb.Fatal(err)
	}
	copy(handle[:], bytes.Repeat([]byte{3}, len(handle)))
	prologue = Prologue{Context: peercontext.Context{AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 2, AuthorizationGeneration: 4, IntentID: "intent_01", OperationID: "operation_01", Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 3}, Carrier: CarrierRelayQUIC, StreamID: "stream_01"}
	copy(prologue.Context.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(prologue.Context.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return initiator, responder, handle, prologue
}

func fuzzSessions(tb testing.TB, initiatorKey, responderKey noise.DHKey, handle [16]byte, prologue Prologue) (*Session, *Session) {
	tb.Helper()
	initiator, err := NewInitiator(initiatorKey, key32(responderKey.Public), prologue, handle)
	if err != nil {
		tb.Fatal(err)
	}
	responder, err := NewResponder(responderKey, key32(initiatorKey.Public), prologue, handle)
	if err != nil {
		tb.Fatal(err)
	}
	request, err := initiator.WriteRequest(nil)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := responder.ReadRequest(request); err != nil {
		tb.Fatal(err)
	}
	response, responderSession, err := responder.WriteResponse(nil)
	if err != nil {
		tb.Fatal(err)
	}
	_, initiatorSession, err := initiator.ReadResponse(response)
	if err != nil {
		tb.Fatal(err)
	}
	return initiatorSession, responderSession
}

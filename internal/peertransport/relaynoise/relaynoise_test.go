package relaynoise

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
)

func TestIKPiggybackAndBidirectionalRecords(t *testing.T) {
	initiator, responder, handle, prologue := identities(t)
	i, err := NewInitiator(initiator, key32(responder.Public), prologue, handle)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponder(responder, key32(initiator.Public), prologue, handle)
	if err != nil {
		t.Fatal(err)
	}
	requestCanary := []byte("private-request-canary")
	request, err := i.WriteRequest(requestCanary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(request, requestCanary) {
		t.Fatal("request payload visible in IK message")
	}
	gotRequest, err := r.ReadRequest(request)
	if err != nil || !bytes.Equal(gotRequest, requestCanary) {
		t.Fatalf("request=%q err=%v", gotRequest, err)
	}
	responseCanary := []byte("private-response-canary")
	response, responderSession, err := r.WriteResponse(responseCanary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(response, responseCanary) {
		t.Fatal("response payload visible in IK message")
	}
	gotResponse, initiatorSession, err := i.ReadResponse(response)
	if err != nil || !bytes.Equal(gotResponse, responseCanary) {
		t.Fatalf("response=%q err=%v", gotResponse, err)
	}
	binding := initiatorSession.ChannelBinding()
	if binding != responderSession.ChannelBinding() || allZero(binding[:]) {
		t.Fatal("channel binding mismatch")
	}

	private := []byte("terminal private content")
	record, err := initiatorSession.Seal(private, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(record) != headerLength+len(private)+authenticationBytes || bytes.Contains(record, private) {
		t.Fatalf("record length=%d or plaintext visible", len(record))
	}
	opened, closed, err := responderSession.Open(record)
	if err != nil || closed || !bytes.Equal(opened, private) {
		t.Fatalf("opened=%q closed=%v err=%v", opened, closed, err)
	}
	reply, err := responderSession.Seal([]byte("reply"), true)
	if err != nil {
		t.Fatal(err)
	}
	opened, closed, err = initiatorSession.Open(reply)
	if err != nil || !closed || string(opened) != "reply" {
		t.Fatalf("opened=%q closed=%v err=%v", opened, closed, err)
	}
	if _, _, err := initiatorSession.Open(reply); !errors.Is(err, ErrProtocol) {
		t.Fatalf("record after close err=%v", err)
	}
}

func TestIKRejectsWrongStaticAndPrologue(t *testing.T) {
	initiator, responder, handle, prologue := identities(t)
	wrong, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Prologue){
		"account": func(value *Prologue) { value.Context.AccountID = "account_02" },
		"attempt": func(value *Prologue) { value.Context.AttemptGeneration++ },
		"carrier": func(value *Prologue) { value.Carrier = CarrierWSS },
	} {
		t.Run(name, func(t *testing.T) {
			i, _ := NewInitiator(initiator, key32(responder.Public), prologue, handle)
			changed := prologue
			mutate(&changed)
			r, _ := NewResponder(responder, key32(initiator.Public), changed, handle)
			message, _ := i.WriteRequest([]byte("private"))
			if _, err := r.ReadRequest(message); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	i, _ := NewInitiator(initiator, key32(responder.Public), prologue, handle)
	r, _ := NewResponder(responder, key32(wrong.Public), prologue, handle)
	message, _ := i.WriteRequest(nil)
	if _, err := r.ReadRequest(message); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong initiator err=%v", err)
	}
}

func TestTransportOnlyPrologueBindsReusableTransport(t *testing.T) {
	_, _, _, legacy := identities(t)
	transport := peercontext.Transport{
		AccountID: legacy.Context.AccountID, UserID: legacy.Context.UserID,
		DeviceID: legacy.Context.DeviceID, MachineID: legacy.Context.MachineID,
		InitiatorCertificateHash: legacy.Context.InitiatorCertificateHash,
		ResponderCertificateHash: legacy.Context.ResponderCertificateHash,
		HostGeneration:           legacy.Context.HostGeneration, AuthorizationGeneration: legacy.Context.AuthorizationGeneration,
		TransportID: legacy.Context.IntentID, InitiatorRole: legacy.Context.InitiatorRole,
		ResponderRole: legacy.Context.ResponderRole, AttemptGeneration: legacy.Context.AttemptGeneration,
	}
	prologue := Prologue{Transport: transport, Carrier: CarrierRelayQUIC, StreamID: "authorized-stream"}
	encoded, err := prologue.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if encoded[4] != 2 {
		t.Fatalf("protocol version=%d", encoded[4])
	}
	changed := prologue
	changed.Transport.TransportID = "transport_02"
	other, err := changed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded, other) {
		t.Fatal("transport identity was not bound into the Noise prologue")
	}
}

func TestRecordRejectsReplayGapTamperDirectionAndHandle(t *testing.T) {
	for name, test := range map[string]struct {
		mutate func([]byte)
		want   error
		replay bool
	}{
		"replay":    {want: ErrReplay, replay: true},
		"gap":       {mutate: func(record []byte) { binary.BigEndian.PutUint64(record[18:26], 9) }, want: ErrReplay},
		"tag":       {mutate: func(record []byte) { record[len(record)-1] ^= 1 }, want: ErrAuthentication},
		"direction": {mutate: func(record []byte) { record[1] |= flagResponder }, want: ErrProtocol},
		"handle":    {mutate: func(record []byte) { record[2] ^= 1 }, want: ErrProtocol},
	} {
		t.Run(name, func(t *testing.T) {
			initiatorSession, responderSession := sessions(t)
			record, _ := initiatorSession.Seal([]byte("private"), false)
			if test.replay {
				if _, _, err := responderSession.Open(record); err != nil {
					t.Fatal(err)
				}
			} else {
				test.mutate(record)
			}
			if _, _, err := responderSession.Open(record); !errors.Is(err, test.want) {
				t.Fatalf("err=%v want=%v", err, test.want)
			}
			if _, _, err := responderSession.Open(record); !errors.Is(err, ErrProtocol) {
				t.Fatalf("poisoned stream err=%v", err)
			}
		})
	}
}

func TestOversizedHandshakePayloadPoisonsAttempt(t *testing.T) {
	initiator, responder, handle, prologue := identities(t)
	i, _ := NewInitiator(initiator, key32(responder.Public), prologue, handle)
	if _, err := i.WriteRequest(make([]byte, 65535)); !errors.Is(err, ErrLimit) {
		t.Fatalf("err=%v", err)
	}
	if _, err := i.WriteRequest(nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("poisoned attempt err=%v", err)
	}
}

func TestConcurrentSealAssignsUniqueSequences(t *testing.T) {
	initiatorSession, _ := sessions(t)
	const count = 32
	sequences := make(chan uint64, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, err := initiatorSession.Seal([]byte("x"), false)
			if err != nil {
				t.Error(err)
				return
			}
			sequences <- binary.BigEndian.Uint64(record[18:26])
		}()
	}
	wait.Wait()
	close(sequences)
	seen := make(map[uint64]bool, count)
	for sequence := range sequences {
		if seen[sequence] {
			t.Fatalf("duplicate sequence %d", sequence)
		}
		seen[sequence] = true
	}
	if len(seen) != count {
		t.Fatalf("sequences=%d", len(seen))
	}
}

func TestRecordSequenceExhaustionRequiresRekeyWithoutWrap(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	initiatorSession.send.sequence = softRekeySequence - 1
	record, err := initiatorSession.Seal(nil, false)
	if err != nil || binary.BigEndian.Uint64(record[18:26]) != softRekeySequence-1 || initiatorSession.send.sequence != softRekeySequence || !initiatorSession.RekeyNeeded() || initiatorSession.NextRekeyDelay() != 0 {
		t.Fatal("sequence exhaustion did not require immediate rekey")
	}
	select {
	case <-initiatorSession.RekeyEvents():
	default:
		t.Fatal("sequence exhaustion did not wake rekey supervisor")
	}
	initiatorSession.send.sequence = hardRekeySequence
	for range 2 {
		if _, err := initiatorSession.Seal(nil, false); !errors.Is(err, ErrRekeyRequired) || initiatorSession.send.sequence != hardRekeySequence {
			t.Fatalf("seal sequence=%d error=%v", initiatorSession.send.sequence, err)
		}
	}
	responderSession.receive.sequence = math.MaxUint64
	if _, _, err := responderSession.Open(record); !errors.Is(err, ErrRekeyRequired) || responderSession.receive.sequence != math.MaxUint64 {
		t.Fatalf("open sequence=%d error=%v", responderSession.receive.sequence, err)
	}
	if _, _, err := responderSession.Open(record); !errors.Is(err, ErrProtocol) {
		t.Fatalf("exhausted receiver was not poisoned: %v", err)
	}
}

func TestRekeyPolicySignalsSoftBoundaryAndAllowsTrafficUntilHardBoundary(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	policy := RekeyPolicy{Bytes: 3, HardBytes: 6, SoftAge: time.Minute, HardAge: 2 * time.Minute}
	if err := initiatorSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := responderSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	record, err := initiatorSession.Seal([]byte("abc"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responderSession.Open(record); err != nil {
		t.Fatal(err)
	}
	if !initiatorSession.RekeyNeeded() || !responderSession.RekeyNeeded() {
		t.Fatal("soft rekey boundary was not reported")
	}
	record, err = initiatorSession.Seal([]byte("de"), false)
	if err != nil {
		t.Fatalf("traffic before hard boundary stopped: %v", err)
	}
	if _, _, err := responderSession.Open(record); err != nil {
		t.Fatalf("receive before hard boundary stopped: %v", err)
	}
	if _, err := initiatorSession.Seal([]byte("fg"), false); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("hard byte boundary err=%v", err)
	}
}

func TestReceiveRejectsRecordCrossingHardRekeyBoundary(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	if err := initiatorSession.ConfigureRekeyPolicy(RekeyPolicy{Bytes: 100, HardBytes: 100, SoftAge: time.Minute, HardAge: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := responderSession.ConfigureRekeyPolicy(RekeyPolicy{Bytes: 3, HardBytes: 5, SoftAge: time.Minute, HardAge: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	first, _ := initiatorSession.Seal([]byte("abc"), false)
	if _, _, err := responderSession.Open(first); err != nil {
		t.Fatal(err)
	}
	second, _ := initiatorSession.Seal([]byte("def"), false)
	if _, _, err := responderSession.Open(second); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("receive hard boundary err=%v", err)
	}
	if _, _, err := responderSession.Open(second); !errors.Is(err, ErrProtocol) {
		t.Fatalf("receiver was not poisoned: %v", err)
	}
}

func TestReceiveAuthenticatesRecordBeforeHardBoundaryDecision(t *testing.T) {
	initiatorSession, responderSession := sessions(t)
	if err := initiatorSession.ConfigureRekeyPolicy(RekeyPolicy{Bytes: 10, HardBytes: 10, SoftAge: time.Minute, HardAge: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := responderSession.ConfigureRekeyPolicy(RekeyPolicy{Bytes: 3, HardBytes: 5, SoftAge: time.Minute, HardAge: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	first, _ := initiatorSession.Seal([]byte("abc"), false)
	if _, _, err := responderSession.Open(first); err != nil {
		t.Fatal(err)
	}
	// The sender's larger hard limit allows a record that the receiver would
	// reject. Corrupting its tag must make authentication win.
	second, _ := initiatorSession.Seal([]byte("de"), false)
	second[len(second)-1] ^= 1
	if _, _, err := responderSession.Open(second); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered boundary record err=%v", err)
	}
}

func TestRekeyPolicyEnforcesHardAge(t *testing.T) {
	initiatorSession, _ := sessions(t)
	if err := initiatorSession.ConfigureRekeyPolicy(RekeyPolicy{Bytes: 10, HardBytes: 20, SoftAge: time.Minute, HardAge: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	initiatorSession.send.started = time.Now().Add(-3 * time.Minute)
	if _, err := initiatorSession.Seal(nil, false); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("hard age err=%v", err)
	}
}

func TestRekeyPolicyRejectsRaisedOrLateConfiguration(t *testing.T) {
	initiatorSession, _ := sessions(t)
	defaults := DevelopmentRekeyPolicy()
	raised := defaults
	raised.HardBytes++
	if err := initiatorSession.ConfigureRekeyPolicy(raised); err == nil {
		t.Fatal("raised hard boundary accepted")
	}
	if _, err := initiatorSession.Seal([]byte("x"), false); err != nil {
		t.Fatal(err)
	}
	if err := initiatorSession.ConfigureRekeyPolicy(defaults); err == nil {
		t.Fatal("late policy change accepted")
	}
}

func sessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	initiator, responder, handle, prologue := identities(t)
	i, _ := NewInitiator(initiator, key32(responder.Public), prologue, handle)
	r, _ := NewResponder(responder, key32(initiator.Public), prologue, handle)
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

func identities(t *testing.T) (initiator, responder noise.DHKey, handle [16]byte, prologue Prologue) {
	t.Helper()
	initiator, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	responder, err = GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], bytes.Repeat([]byte{3}, 16))
	prologue = Prologue{Context: peercontext.Context{AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01", HostGeneration: 2, AuthorizationGeneration: 4, IntentID: "intent_01", OperationID: "operation_01", Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 3}, Carrier: CarrierRelayQUIC, StreamID: "stream_01"}
	copy(prologue.Context.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(prologue.Context.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return initiator, responder, handle, prologue
}

func key32(value []byte) [32]byte {
	var result [32]byte
	copy(result[:], value)
	return result
}

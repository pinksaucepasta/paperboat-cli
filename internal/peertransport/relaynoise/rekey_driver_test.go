package relaynoise

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type channelRekeyCarrier struct {
	send    chan<- []byte
	receive <-chan []byte
}

func (c channelRekeyCarrier) SendRekeyRecord(ctx context.Context, record []byte) error {
	copyRecord := append([]byte(nil), record...)
	select {
	case c.send <- copyRecord:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c channelRekeyCarrier) ReceiveRekeyRecord(ctx context.Context) ([]byte, error) {
	select {
	case record := <-c.receive:
		return record, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestRekeyDriversCompleteInBandTransition(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, responderSession := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	prior := initiatorSession.ChannelBinding()
	left, right := net.Pipe()
	initiatorCarrier, _ := NewStreamCarrier(left)
	responderCarrier, _ := NewStreamCarrier(right)
	defer initiatorCarrier.Close()
	defer responderCarrier.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		errs <- RunResponderRekey(ctx, responderSession, responderCarrier, responderKey, key32(initiatorKey.Public), prologue, 2)
	}()
	go func() {
		errs <- RunInitiatorRekey(ctx, initiatorSession, initiatorCarrier, initiatorKey, key32(responderKey.Public), prologue, 2)
	}()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if initiatorSession.ChannelBinding() == prior || initiatorSession.ChannelBinding() != responderSession.ChannelBinding() {
		t.Fatal("drivers did not converge on fresh channel binding")
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- initiatorCarrier.Send(ctx, initiatorSession, []byte("after-rekey"), false) }()
	record, err := responderCarrier.ReceiveRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if payload, _, err := responderSession.Open(record); err != nil || string(payload) != "after-rekey" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
}

func TestRekeyDriversUseReservedTerminalSequences(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, responderSession := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	initiatorSession.send.sequence = hardRekeySequence
	initiatorSession.receive.sequence = hardRekeySequence
	responderSession.send.sequence = hardRekeySequence
	responderSession.receive.sequence = hardRekeySequence
	i2r, r2i := make(chan []byte, sequenceRekeyReserve), make(chan []byte, sequenceRekeyReserve)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		errs <- RunResponderRekey(ctx, responderSession, channelRekeyCarrier{send: r2i, receive: i2r}, responderKey, key32(initiatorKey.Public), prologue, 2)
	}()
	go func() {
		errs <- RunInitiatorRekey(ctx, initiatorSession, channelRekeyCarrier{send: i2r, receive: r2i}, initiatorKey, key32(responderKey.Public), prologue, 2)
	}()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if initiatorSession.send.sequence != 1 || initiatorSession.receive.sequence != 0 || responderSession.send.sequence != 0 || responderSession.receive.sequence != 1 {
		t.Fatalf("sequences were not reset before final acknowledgement: initiator=%d/%d responder=%d/%d", initiatorSession.send.sequence, initiatorSession.receive.sequence, responderSession.send.sequence, responderSession.receive.sequence)
	}
}

func TestInterruptedRekeyPoisonsSession(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, _ := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	outbound, inbound := make(chan []byte, 1), make(chan []byte)
	carrier := channelRekeyCarrier{send: outbound, receive: inbound}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RunInitiatorRekey(ctx, initiatorSession, carrier, initiatorKey, key32(responderKey.Public), prologue, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if _, err := initiatorSession.Seal(nil, false); !errors.Is(err, ErrProtocol) {
		t.Fatalf("interrupted session remained usable: %v", err)
	}
}

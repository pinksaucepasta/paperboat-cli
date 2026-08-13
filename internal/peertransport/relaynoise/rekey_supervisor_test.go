package relaynoise

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInitiatorRekeySupervisorTriggersAtByteBoundary(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, responderSession := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	policy := RekeyPolicy{Bytes: 1, HardBytes: 1 << 20, SoftAge: time.Minute, HardAge: 2 * time.Minute}
	if err := initiatorSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := responderSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	i2r, r2i := make(chan []byte, 8), make(chan []byte, 8)
	initiatorCarrier := channelRekeyCarrier{send: i2r, receive: r2i}
	responderCarrier := channelRekeyCarrier{send: r2i, receive: i2r}
	supervisor, err := NewInitiatorRekeySupervisor(InitiatorRekeySupervisorConfig{Session: initiatorSession, Carrier: initiatorCarrier, LocalStatic: initiatorKey, ResponderPublic: key32(responderKey.Public), Prologue: prologue, FirstRekeyGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- supervisor.Run(ctx) }()
	responderDone := make(chan error, 1)
	go func() {
		responderDone <- RunResponderRekey(ctx, responderSession, responderCarrier, responderKey, key32(initiatorKey.Public), prologue, 2)
	}()
	prior := initiatorSession.ChannelBinding()
	record, err := initiatorSession.Seal([]byte("trigger"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := responderSession.Open(record); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-responderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for initiatorSession.ChannelBinding() == prior || initiatorSession.ChannelBinding() != responderSession.ChannelBinding() {
		select {
		case <-ctx.Done():
			t.Fatal("threshold-triggered rekey did not converge")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-supervisorDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor err=%v", err)
	}
}

func TestInitiatorRekeySupervisorRejectsConcurrentRun(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, _ := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	carrier := channelRekeyCarrier{send: make(chan []byte), receive: make(chan []byte)}
	supervisor, _ := NewInitiatorRekeySupervisor(InitiatorRekeySupervisorConfig{Session: initiatorSession, Carrier: carrier, LocalStatic: initiatorKey, ResponderPublic: key32(responderKey.Public), Prologue: prologue, FirstRekeyGeneration: 2})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		supervisor.mu.Lock()
		running := supervisor.running
		supervisor.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("supervisor did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := supervisor.Run(context.Background()); err == nil {
		t.Fatal("concurrent run accepted")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown err=%v", err)
	}
}

func TestInitiatorRekeySupervisorTriggersAtAgeBoundary(t *testing.T) {
	initiatorKey, responderKey, handle, prologue := identities(t)
	initiatorSession, responderSession := sessionsForIdentities(t, initiatorKey, responderKey, handle, prologue)
	policy := RekeyPolicy{Bytes: 1 << 20, HardBytes: 2 << 20, SoftAge: 20 * time.Millisecond, HardAge: time.Second}
	if err := initiatorSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := responderSession.ConfigureRekeyPolicy(policy); err != nil {
		t.Fatal(err)
	}
	i2r, r2i := make(chan []byte, 8), make(chan []byte, 8)
	supervisor, _ := NewInitiatorRekeySupervisor(InitiatorRekeySupervisorConfig{Session: initiatorSession, Carrier: channelRekeyCarrier{send: i2r, receive: r2i}, LocalStatic: initiatorKey, ResponderPublic: key32(responderKey.Public), Prologue: prologue, FirstRekeyGeneration: 2})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- supervisor.Run(ctx) }()
	responderDone := make(chan error, 1)
	go func() {
		responderDone <- RunResponderRekey(ctx, responderSession, channelRekeyCarrier{send: r2i, receive: i2r}, responderKey, key32(initiatorKey.Public), prologue, 2)
	}()
	select {
	case err := <-responderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-supervisorDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor err=%v", err)
	}
}

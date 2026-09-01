package relaycarrier

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

func TestRelayHealthExchangeAcrossQUICAndWSS(t *testing.T) {
	for _, carrier := range []relaynoise.Carrier{relaynoise.CarrierRelayQUIC, relaynoise.CarrierWSS} {
		t.Run(carrierName(carrier), func(t *testing.T) {
			var client, server *Connection
			var capture *wireCapture
			if carrier == relaynoise.CarrierRelayQUIC {
				clientSession, serverSession := quicPair(t)
				client, _ = NewRelayQUIC(clientSession, DevelopmentConfig())
				server, _ = NewRelayQUIC(serverSession, DevelopmentConfig())
			} else {
				client, server, capture = wssPair(t, 4)
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			initiator, responder, handle, prologue := testIdentities(t, carrier)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			served := make(chan error, 1)
			go func() {
				served <- server.AcceptHealth(ctx, ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle})
			}()
			var nonce [16]byte
			copy(nonce[:], "relay-health-one")
			_, err := client.HealthExchange(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle}, nonce)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			if capture != nil && (bytes.Contains(capture.Bytes(), healthMagic[:]) || bytes.Contains(capture.Bytes(), nonce[:])) {
				t.Fatal("relay health payload visible on WSS carrier")
			}
		})
	}
}

func TestRelayHealthConnectionPublishesPathBoundCapability(t *testing.T) {
	for _, carrier := range []relaynoise.Carrier{relaynoise.CarrierRelayQUIC, relaynoise.CarrierWSS} {
		t.Run(carrierName(carrier), func(t *testing.T) {
			var connection, serverConnection *Connection
			var capture *wireCapture
			if carrier == relaynoise.CarrierRelayQUIC {
				client, server := quicPair(t)
				connection, _ = NewRelayQUIC(client, DevelopmentConfig())
				serverConnection, _ = NewRelayQUIC(server, DevelopmentConfig())
			} else {
				connection, serverConnection, capture = wssPair(t, 2)
			}
			t.Cleanup(func() { _ = serverConnection.Close() })
			initiator, responder, _, prologue := testIdentities(t, carrier)
			var handlesMu sync.Mutex
			var handles [][16]byte
			handleReady := make(chan [16]byte, 2)
			source := HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (InitiatorConfig, error) {
				handlesMu.Lock()
				handles = append(handles, handle)
				handlesMu.Unlock()
				handleReady <- handle
				return InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle}, nil
			})
			wrapped, err := NewHealthConnection(connection, source)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = wrapped.Close() })
			path := connectionmanager.PathRelayQUIC
			if carrier == relaynoise.CarrierWSS {
				path = connectionmanager.PathWSS
			}
			if wrapped.State() != connectionmanager.StateReady {
				t.Fatalf("initial state=%d", wrapped.State())
			}
			served := make(chan error, 2)
			go func() {
				handle := <-handleReady
				served <- serverConnection.AcceptHealth(context.Background(), ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle})
			}()
			var nonce [16]byte
			copy(nonce[:], "initial-relay-ok")
			if err := wrapped.AdmitInitialHealth(context.Background(), nonce); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			initialNonce := nonce
			if wrapped.State() != connectionmanager.StateTrusted {
				t.Fatalf("admitted state=%d", wrapped.State())
			}
			transport, err := connectionmanager.ConnectionHealthTransport(connectionmanager.Selection{Generation: 3, Path: path, Connection: wrapped})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := transport.(HealthTransport); !ok {
				t.Fatalf("transport=%T", transport)
			}
			go func() {
				handle := <-handleReady
				served <- serverConnection.AcceptHealth(context.Background(), ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle})
			}()
			copy(nonce[:], "periodic-relay-ok")
			if _, err := transport.HealthExchange(context.Background(), nonce); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			if capture != nil && (bytes.Contains(capture.Bytes(), healthMagic[:]) || bytes.Contains(capture.Bytes(), initialNonce[:]) || bytes.Contains(capture.Bytes(), nonce[:])) {
				t.Fatal("repeated relay health payload visible on WSS carrier")
			}
			handlesMu.Lock()
			if len(handles) != 2 || handles[0] == ([16]byte{}) || handles[1] == ([16]byte{}) || handles[0] == handles[1] {
				t.Fatalf("health handles=%x", handles)
			}
			handlesMu.Unlock()
			if _, err := connectionmanager.ConnectionHealthTransport(connectionmanager.Selection{Generation: 3, Path: connectionmanager.PathDirectQUIC, Connection: wrapped}); err == nil {
				t.Fatal("accepted relay health capability as direct QUIC")
			}
		})
	}
}

func TestRelayHealthNegotiatesPeriodicResponderHandles(t *testing.T) {
	for _, carrier := range []relaynoise.Carrier{relaynoise.CarrierRelayQUIC, relaynoise.CarrierWSS} {
		t.Run(carrierName(carrier), func(t *testing.T) {
			var client, server *Connection
			if carrier == relaynoise.CarrierRelayQUIC {
				clientSession, serverSession := quicPair(t)
				client, _ = NewRelayQUIC(clientSession, DevelopmentConfig())
				server, _ = NewRelayQUIC(serverSession, DevelopmentConfig())
			} else {
				client, server, _ = wssPair(t, 4)
			}
			initiator, responder, bootstrapHandle, prologue := testIdentities(t, carrier)
			initiatorSource := HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (InitiatorConfig, error) {
				return InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle}, nil
			})
			responderSource := HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (ResponderConfig, error) {
				return ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle, Authorize: func(context.Context, []byte) ([]byte, error) { return nil, nil }}, nil
			})
			health, err := NewHealthConnection(client, initiatorSource)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			prefixReady := make(chan [8]byte, 1)
			served := make(chan error, 1)
			go func() {
				prefix, acceptErr := server.AcceptInitialHealth(ctx, ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: bootstrapHandle})
				if acceptErr != nil {
					served <- acceptErr
					return
				}
				prefixReady <- prefix.Prefix
				served <- server.ServeHealth(ctx, prefix.Prefix, responderSource)
			}()
			var initialNonce [16]byte
			copy(initialNonce[:], "negotiated-start")
			if err := health.AdmitInitialRelayHealth(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: bootstrapHandle}, initialNonce); err != nil {
				t.Fatal(err)
			}
			if prefix := <-prefixReady; prefix == [8]byte{} || prefix != health.transport.handles.prefix {
				t.Fatalf("negotiated prefix=%x local=%x", prefix, health.transport.handles.prefix)
			}
			if binding, err := health.CandidateBinding(); err != nil || binding == [32]byte{} {
				t.Fatalf("candidate binding=%x error=%v", binding, err)
			}
			transport, err := connectionmanager.ConnectionHealthTransport(connectionmanager.Selection{Generation: 1, Path: health.path, Connection: health})
			if err != nil {
				t.Fatal(err)
			}
			var periodicNonce [16]byte
			copy(periodicNonce[:], "negotiated-next")
			if _, err := transport.HealthExchange(ctx, periodicNonce); err != nil {
				t.Fatal(err)
			}
			cancel()
			_ = health.Close()
			_ = server.Close()
			if err := <-served; err == nil {
				t.Fatal("periodic responder returned success without shutdown")
			}
		})
	}
}

func TestRelayHealthResponderSurvivesAbortedProbe(t *testing.T) {
	for _, carrier := range []relaynoise.Carrier{relaynoise.CarrierRelayQUIC, relaynoise.CarrierWSS} {
		t.Run(carrierName(carrier), func(t *testing.T) {
			var client, server *Connection
			if carrier == relaynoise.CarrierRelayQUIC {
				clientSession, serverSession := quicPair(t)
				client, _ = NewRelayQUIC(clientSession, DevelopmentConfig())
				server, _ = NewRelayQUIC(serverSession, DevelopmentConfig())
			} else {
				client, server, _ = wssPair(t, 4)
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			initiator, responder, _, prologue := testIdentities(t, carrier)
			var prefix [8]byte
			copy(prefix[:], "recover1")
			initiatorSource := HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (InitiatorConfig, error) {
				return InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle}, nil
			})
			responderSource := HealthResponderConfigSourceFunc(func(_ context.Context, handle [16]byte) (ResponderConfig, error) {
				return ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			served := make(chan error, 1)
			go func() { served <- server.ServeHealth(ctx, prefix, responderSource) }()

			handles := &healthHandleSequence{prefix: prefix}
			abortedHandle, err := handles.nextHandle()
			if err != nil {
				t.Fatal(err)
			}
			aborted, err := client.openHandle(ctx, abortedHandle, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := aborted.Close(); err != nil {
				t.Fatal(err)
			}

			transport := HealthTransport{Connection: client, source: initiatorSource, handles: handles}
			var nonce [16]byte
			copy(nonce[:], "after-abort-ok")
			if _, err := transport.HealthExchange(ctx, nonce); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-served:
				t.Fatalf("responder stopped after aborted probe: %v", err)
			default:
			}
		})
	}
}

func TestRelayHealthConnectionRejectsInvalidOrClosedConfiguration(t *testing.T) {
	clientSession, serverSession := quicPair(t)
	connection, _ := NewRelayQUIC(clientSession, DevelopmentConfig())
	t.Cleanup(func() { _ = serverSession.Close() })
	if _, err := NewHealthConnection(connection, nil); err == nil {
		t.Fatal("accepted nil health configuration source")
	}
	_ = connection.Close()
	if _, err := NewHealthConnection(connection, HealthConfigSourceFunc(func(context.Context, [16]byte) (InitiatorConfig, error) {
		return InitiatorConfig{}, nil
	})); err == nil {
		t.Fatal("accepted closed relay connection")
	}
}

func TestInitialHealthClassifiesCarrierShutdownWithoutWeakeningProtocolFailures(t *testing.T) {
	transient := initialHealthFailure(connectionmanager.PathRelayQUIC, yamux.ErrSessionShutdown)
	var failure *connectionmanager.Failure
	if !errors.As(transient, &failure) || failure.Class != connectionmanager.FailureTransient || failure.Path != connectionmanager.PathRelayQUIC || !errors.Is(transient, yamux.ErrSessionShutdown) {
		t.Fatalf("carrier shutdown classification=%v", transient)
	}
	protocol := relaynoise.ErrProtocol
	if got := initialHealthFailure(connectionmanager.PathRelayQUIC, protocol); got != protocol {
		t.Fatalf("protocol failure was reclassified: %v", got)
	}
}

func TestRelayHealthTransportRejectsMismatchedHandleAndOverflow(t *testing.T) {
	connection := &Connection{carrier: relaynoise.CarrierRelayQUIC}
	transport := HealthTransport{
		Connection: connection,
		handles:    &healthHandleSequence{},
		source: HealthConfigSourceFunc(func(context.Context, [16]byte) (InitiatorConfig, error) {
			return InitiatorConfig{}, nil
		}),
	}
	if _, err := transport.HealthExchange(context.Background(), [16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched handle error=%v", err)
	}
	var calls atomic.Uint32
	transport.source = HealthConfigSourceFunc(func(context.Context, [16]byte) (InitiatorConfig, error) {
		calls.Add(1)
		return InitiatorConfig{}, nil
	})
	transport.handles.next.Store(^uint64(0))
	if _, err := transport.HealthExchange(context.Background(), [16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overflow error=%v", err)
	}
	if _, err := transport.HealthExchange(context.Background(), [16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("post-overflow error=%v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("requested configuration after handle overflow")
	}
}

func TestRelayHealthHandleSequenceExhaustsOnceUnderConcurrency(t *testing.T) {
	sequence := &healthHandleSequence{prefix: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	sequence.next.Store(^uint64(0) - 1)
	type result struct {
		handle [16]byte
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			handle, err := sequence.nextHandle()
			results <- result{handle: handle, err: err}
		}()
	}
	close(start)
	var succeeded, rejected int
	for range 2 {
		result := <-results
		if result.err == nil {
			succeeded++
			var prefix, suffix [8]byte
			copy(prefix[:], result.handle[:8])
			copy(suffix[:], result.handle[8:])
			if prefix != sequence.prefix || suffix != ([8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
				t.Fatalf("final handle=%x", result.handle)
			}
		} else if errors.Is(result.err, ErrInvalid) {
			rejected++
		} else {
			t.Fatalf("unexpected error=%v", result.err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("succeeded=%d rejected=%d", succeeded, rejected)
	}
	if _, err := sequence.nextHandle(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("exhausted sequence error=%v", err)
	}
}

func TestRelayHealthPayloadRejectsMalformedValues(t *testing.T) {
	var nonce [16]byte
	valid := healthPayload(1, nonce)
	for _, value := range [][]byte{nil, valid[:len(valid)-1], append([]byte(nil), valid...)} {
		if len(value) == len(valid) {
			value[5] = 2
		}
		if _, err := parseHealthPayload(value, 1); err == nil {
			t.Fatalf("accepted malformed payload %x", value)
		}
	}
}

func carrierName(carrier relaynoise.Carrier) string {
	if carrier == relaynoise.CarrierRelayQUIC {
		return "relay_quic"
	}
	return "relay_wss"
}

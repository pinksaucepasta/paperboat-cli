package networkadaptation

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type pmtuExchangeFunc func(context.Context, []byte) ([]byte, error)

func (f pmtuExchangeFunc) ExchangePMTU(ctx context.Context, datagram []byte) ([]byte, error) {
	return f(ctx, datagram)
}

func TestAuthenticatedPMTUProbeUsesExactPaddedDatagrams(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	responder, err := NewPMTUResponder(key, 1452)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	var lengths []int
	exchanger := pmtuExchangeFunc(func(_ context.Context, datagram []byte) ([]byte, error) {
		lengths = append(lengths, len(datagram))
		response, err := responder.Handle(datagram)
		if err == nil && len(response) != len(datagram) {
			t.Fatalf("response length = %d, request = %d", len(response), len(datagram))
		}
		return response, err
	})
	prober, err := NewAuthenticatedPMTUProber(key, 1452, exchanger)
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	for _, size := range []uint16{1200, 1378, 1452} {
		result, err := prober.ProbePayload(context.Background(), size)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Supported || result.At.IsZero() {
			t.Fatalf("size=%d result=%+v", size, result)
		}
	}
	for index, size := range []int{1200, 1378, 1452} {
		if lengths[index] != size {
			t.Fatalf("lengths=%v", lengths)
		}
	}
}

func TestPMTUResponderAuthenticatesBeforeAcceptingHeader(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	responder, _ := NewPMTUResponder(key, 1452)
	defer responder.Close()
	frame, _ := buildPMTUFrame(key, pmtuFrameRequest, 1200, [16]byte{1})
	for name, mutate := range map[string]func([]byte){
		"magic":   func(value []byte) { value[0] ^= 1 },
		"version": func(value []byte) { value[4]++ },
		"type":    func(value []byte) { value[5] = pmtuFrameResponse },
		"size":    func(value []byte) { value[7]++ },
		"padding": func(value []byte) { value[100] ^= 1 },
		"tag":     func(value []byte) { value[len(value)-1] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), frame...)
			mutate(tampered)
			if _, err := responder.Handle(tampered); err == nil {
				t.Fatal("tampered datagram accepted")
			}
		})
	}
	wrongKey, _ := NewPMTUResponder(bytes.Repeat([]byte{9}, 32), 1452)
	defer wrongKey.Close()
	if _, err := wrongKey.Handle(frame); err == nil {
		t.Fatal("cross-key datagram accepted")
	}
}

func TestAuthenticatedPMTUProbeRejectsResponseReplayAndTampering(t *testing.T) {
	key := bytes.Repeat([]byte{10}, 32)
	for name, exchange := range map[string]pmtuExchangeFunc{
		"nonce": func(_ context.Context, request []byte) ([]byte, error) {
			return buildPMTUFrame(key, pmtuFrameResponse, uint16(len(request)), [16]byte{99})
		},
		"authentication": func(_ context.Context, request []byte) ([]byte, error) {
			nonce, _ := parsePMTUFrame(key, request, pmtuFrameRequest, uint16(len(request)))
			response, _ := buildPMTUFrame(key, pmtuFrameResponse, uint16(len(request)), nonce)
			response[100] ^= 1
			return response, nil
		},
		"length": func(_ context.Context, request []byte) ([]byte, error) {
			return make([]byte, len(request)-1), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			prober, _ := NewAuthenticatedPMTUProber(key, 1452, exchange)
			defer prober.Close()
			if result, err := prober.ProbePayload(context.Background(), 1200); err == nil || result.Supported {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
}

func TestAuthenticatedPMTUProbeClassifiesOnlyExplicitReachability(t *testing.T) {
	key := bytes.Repeat([]byte{11}, 32)
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, ErrPMTUProbeUnreachable
	}))
	result, err := prober.ProbePayload(context.Background(), 1200)
	if err != nil || result.Supported || result.At.IsZero() {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	want := errors.New("socket failure")
	prober, _ = NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, want
	}))
	if _, err := prober.ProbePayload(context.Background(), 1200); !errors.Is(err, want) {
		t.Fatalf("socket error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	prober, _ = NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, ErrPMTUProbeUnreachable
	}))
	if _, err := prober.ProbePayload(canceled, 1200); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestPMTUProbeOwnersEraseSecretsAndRejectUseAfterClose(t *testing.T) {
	key := bytes.Repeat([]byte{12}, 32)
	responder, _ := NewPMTUResponder(key, 1452)
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(_ context.Context, datagram []byte) ([]byte, error) {
		return responder.Handle(datagram)
	}))
	if err := prober.Close(); err != nil || prober.Close() != nil {
		t.Fatal(err)
	}
	if len(prober.key) != 0 {
		t.Fatal("prober retained key")
	}
	if _, err := prober.ProbePayload(context.Background(), 1200); err == nil {
		t.Fatal("closed prober accepted work")
	}
	if err := responder.Close(); err != nil || responder.Close() != nil {
		t.Fatal(err)
	}
	if len(responder.key) != 0 {
		t.Fatal("responder retained key")
	}
	frame := make([]byte, 1200)
	if _, err := responder.Handle(frame); err == nil {
		t.Fatal("closed responder accepted work")
	}
}

func TestAuthenticatedPMTUProbeValidatesBoundsAndTypedNil(t *testing.T) {
	key := bytes.Repeat([]byte{13}, 32)
	var typedNil *nilPMTUExchange
	if _, err := NewAuthenticatedPMTUProber(key, 1452, typedNil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil error = %v", err)
	}
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(context.Context, []byte) ([]byte, error) { return nil, nil }))
	defer prober.Close()
	for _, size := range []uint16{1199, 1453} {
		if _, err := prober.ProbePayload(context.Background(), size); !errors.Is(err, ErrInvalid) {
			t.Fatalf("size=%d error=%v", size, err)
		}
	}
	if _, err := NewPMTUResponder(key[:31], 1452); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short key error = %v", err)
	}
}

type nilPMTUExchange struct{}

func (*nilPMTUExchange) ExchangePMTU(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unreachable")
}

func TestPMTUProbeContextDeadlineDoesNotBecomeNegativeEvidence(t *testing.T) {
	key := bytes.Repeat([]byte{14}, 32)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	prober, _ := NewAuthenticatedPMTUProber(key, 1452, pmtuExchangeFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, ErrPMTUProbeUnreachable
	}))
	defer prober.Close()
	if _, err := prober.ProbePayload(ctx, 1200); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

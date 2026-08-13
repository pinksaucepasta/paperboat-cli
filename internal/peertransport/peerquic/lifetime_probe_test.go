package peerquic

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type pipeProbeStream struct {
	net.Conn
	readCanceled  atomic.Int32
	writeCanceled atomic.Int32
	maximumWrite  int
}

func (s *pipeProbeStream) Write(value []byte) (int, error) {
	if s.maximumWrite > 0 && len(value) > s.maximumWrite {
		value = value[:s.maximumWrite]
	}
	return s.Conn.Write(value)
}

func (s *pipeProbeStream) CancelRead(quic.StreamErrorCode) {
	s.readCanceled.Add(1)
	_ = s.Conn.SetReadDeadline(time.Now())
}

func (s *pipeProbeStream) CancelWrite(quic.StreamErrorCode) {
	s.writeCanceled.Add(1)
	_ = s.Conn.SetWriteDeadline(time.Now())
}

func TestLifetimeProbeChallengeResponseHandlesFragmentedWrites(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := &pipeProbeStream{Conn: clientConn, maximumWrite: 3}
	server := &pipeProbeStream{Conn: serverConn, maximumWrite: 2}
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- serveLifetimeProbe(ctx, server) }()
	var nonce [16]byte
	copy(nonce[:], "unique-challenge")
	if err := exchangeLifetimeProbeIdle(ctx, client, nonce, 1250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestLifetimeProbeRejectsIdleMismatch(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := &pipeProbeStream{Conn: clientConn}
	server := &pipeProbeStream{Conn: serverConn}
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		var request [lifetimeProbeSize]byte
		_, err := io.ReadFull(server, request[:])
		nonce, _, parseErr := parseLifetimeFrameWithIdle(request, lifetimeProbeRequest)
		if err == nil {
			err = parseErr
		}
		if err == nil {
			response := lifetimeFrameWithIdle(lifetimeProbeResponse, nonce, 2*time.Second)
			err = writeFull(server, response[:])
		}
		done <- err
	}()
	if err := exchangeLifetimeProbeIdle(context.Background(), client, [16]byte{1}, time.Second); err == nil {
		t.Fatal("mismatched idle accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLifetimeProbeRejectsInvalidIdleBounds(t *testing.T) {
	if err := exchangeLifetimeProbeIdle(context.Background(), nil, [16]byte{}, 5*time.Minute+time.Millisecond); err == nil {
		t.Fatal("idle over five minutes accepted")
	}
	frame := lifetimeFrameWithIdle(lifetimeProbeRequest, [16]byte{1}, 0)
	binary.BigEndian.PutUint64(frame[22:], uint64((5*time.Minute)/time.Millisecond+1))
	if _, _, err := parseLifetimeFrameWithIdle(frame, lifetimeProbeRequest); err == nil {
		t.Fatal("oversized wire idle accepted")
	}
}

func TestLifetimeProbeRejectsWrongNonceAndFrameType(t *testing.T) {
	for name, response := range map[string][lifetimeProbeSize]byte{
		"nonce": lifetimeFrame(lifetimeProbeResponse, [16]byte{9}),
		"type":  lifetimeFrame(lifetimeProbeRequest, [16]byte{1}),
	} {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			client := &pipeProbeStream{Conn: clientConn}
			server := &pipeProbeStream{Conn: serverConn}
			defer client.Close()
			defer server.Close()
			serverDone := make(chan error, 1)
			go func() {
				var request [lifetimeProbeSize]byte
				_, err := io.ReadFull(server, request[:])
				if err == nil {
					err = writeFull(server, response[:])
				}
				serverDone <- err
			}()
			if err := exchangeLifetimeProbe(context.Background(), client, [16]byte{1}); err == nil {
				t.Fatal("invalid response accepted")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLifetimeProbeServerRejectsMalformedRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := &pipeProbeStream{Conn: clientConn}
	server := &pipeProbeStream{Conn: serverConn}
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- serveLifetimeProbe(context.Background(), server) }()
	invalid := lifetimeFrame(lifetimeProbeResponse, [16]byte{1})
	if err := writeFull(client, invalid[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("response frame accepted as request")
	}
}

func TestLifetimeProbeCancellationInterruptsBlockedIO(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client := &pipeProbeStream{Conn: clientConn}
	server := &pipeProbeStream{Conn: serverConn}
	defer client.Close()
	defer server.Close()
	requestRead := make(chan struct{})
	go func() {
		var request [lifetimeProbeSize]byte
		_, _ = io.ReadFull(server, request[:])
		close(requestRead)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exchangeLifetimeProbe(ctx, client, [16]byte{1}) }()
	<-requestRead
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled exchange succeeded")
	}
	if client.readCanceled.Load() != 1 || client.writeCanceled.Load() != 1 {
		t.Fatalf("cancel read/write = %d/%d", client.readCanceled.Load(), client.writeCanceled.Load())
	}
}

func TestLifetimeProbeClassifiesOnlyResponseDeadlineAsUnreachable(t *testing.T) {
	t.Run("response", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		client := &pipeProbeStream{Conn: clientConn}
		server := &pipeProbeStream{Conn: serverConn}
		defer client.Close()
		defer server.Close()
		requestRead := make(chan struct{})
		go func() {
			var request [lifetimeProbeSize]byte
			_, _ = io.ReadFull(server, request[:])
			close(requestRead)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		err := exchangeLifetimeProbe(ctx, client, [16]byte{1})
		<-requestRead
		if !errors.Is(err, ErrLifetimeProbeUnreachable) {
			t.Fatalf("response deadline error=%v", err)
		}
	})

	t.Run("request_write", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		client := &pipeProbeStream{Conn: clientConn}
		server := &pipeProbeStream{Conn: serverConn}
		defer client.Close()
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		err := exchangeLifetimeProbe(ctx, client, [16]byte{1})
		if err == nil || errors.Is(err, ErrLifetimeProbeUnreachable) {
			t.Fatalf("request-write deadline error=%v", err)
		}
	})
}

func TestBindProbeContextRejectsInvalidInput(t *testing.T) {
	//lint:ignore SA1012 This test verifies that nil contexts fail closed.
	if _, err := bindProbeContext(nil, nil); err == nil {
		t.Fatal("nil context and stream accepted")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	stream := &pipeProbeStream{Conn: left}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	stop, err := bindProbeContext(expired, stream)
	if err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if stop != nil {
		stop()
	}
}

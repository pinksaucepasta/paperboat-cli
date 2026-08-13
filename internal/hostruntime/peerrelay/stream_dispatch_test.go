package peerrelay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
)

type streamCredentialAuthorizer struct {
	frame  protocol.Frame
	closed bool
}

func (a *streamCredentialAuthorizer) Authorize(_ context.Context, frame protocol.Frame) (server.Authorization, error) {
	a.frame = frame
	return server.Authorization{}, nil
}
func (a *streamCredentialAuthorizer) CloseAuthorization() { a.closed = true }

func TestCredentialStreamAuthorizerUsesCanonicalApplicationPolicy(t *testing.T) {
	for consumer, capability := range map[string]string{"terminal": "terminal.v1", "exec": "exec.v1", "ssh": "ssh.v1", "private_preview": "preview.launch.v1", "codex": "codex.connect.v1"} {
		t.Run(consumer, func(t *testing.T) {
			var created *streamCredentialAuthorizer
			authorize := CredentialStreamAuthorizer(func(token string) (server.Authorizer, error) {
				if token != "credential" {
					t.Fatalf("token=%q", token)
				}
				created = &streamCredentialAuthorizer{}
				return created, nil
			})
			header, err := streamauth.New("operation_1", consumer, "stream_1", "credential", time.Now().Add(time.Minute), 1024)
			if err != nil {
				t.Fatal(err)
			}
			if err := authorize(context.Background(), header); err != nil {
				t.Fatal(err)
			}
			if created.frame.Capability != capability || created.frame.OperationID != header.OperationID || created.frame.RequestID != header.StreamID || !created.closed {
				t.Fatalf("frame=%+v closed=%t", created.frame, created.closed)
			}
		})
	}
}

func TestDispatchAuthorizedStreamVerifiesBeforeHandlerAndBoundsBytes(t *testing.T) {
	now := time.Now().UTC().Add(time.Minute)
	header, err := streamauth.New("operation_1", "exec", "native-control", "credential", now, 5)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := header.MarshalBinary()
	left, right := net.Pipe()
	defer left.Close()
	called := false
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- DispatchAuthorizedStream(context.Background(), encoded, right, func(context.Context, streamauth.Header) error { return nil }, func(_ context.Context, got streamauth.Header, conn net.Conn) error {
			called = true
			if got.OperationID != header.OperationID || got.Consumer != header.Consumer {
				return errors.New("wrong header")
			}
			_, err := conn.Write([]byte("123456"))
			return err
		})
	}()
	readDone := make(chan struct{})
	go func() {
		buffer := make([]byte, 8)
		_, _ = left.Read(buffer)
		close(readDone)
	}()
	err = <-dispatchDone
	<-readDone
	if !called || !errors.Is(err, ErrStreamDispatch) {
		t.Fatalf("called=%t err=%v", called, err)
	}
}

func TestDispatchAuthorizedStreamRejectsUnauthorizedBeforeHandler(t *testing.T) {
	header, _ := streamauth.New("operation_1", "exec", "native-control", "credential", time.Now().UTC().Add(time.Minute), 5)
	encoded, _ := header.MarshalBinary()
	left, right := net.Pipe()
	defer left.Close()
	called := false
	err := DispatchAuthorizedStream(context.Background(), encoded, right, func(context.Context, streamauth.Header) error { return errors.New("denied") }, func(context.Context, streamauth.Header, net.Conn) error { called = true; return nil })
	if !errors.Is(err, ErrStreamDispatch) || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}

type halfCloseDispatchConn struct {
	net.Conn
	halfClosed bool
}

func (c *halfCloseDispatchConn) CloseWrite() error {
	c.halfClosed = true
	return nil
}

func TestBoundedConnPreservesTransportHalfClose(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	inner := &halfCloseDispatchConn{Conn: right}
	bounded := &boundedConn{Conn: inner, remaining: 1024}
	if err := bounded.CloseWrite(); err != nil || !inner.halfClosed || bounded.closed.Load() {
		t.Fatalf("close-write err=%v half=%t closed=%t", err, inner.halfClosed, bounded.closed.Load())
	}
}

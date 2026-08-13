package peerquic_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

func TestOwnedTransportCloseInterruptsBlockedQUICShutdown(t *testing.T) {
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.Listen(serverConn, serverTLS, peerquic.ClassPreview)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *peerquic.Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- session
	}()
	client, err := peerquic.Dial(ctx, clientConn, clientTLS, peerquic.ClassPreview)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case acceptErr := <-acceptErrors:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(acceptErr)
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(ctx.Err())
	}

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("owned QUIC transport close blocked")
	}
	go func() { closed <- server.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("accepted QUIC session close blocked after peer transport shutdown")
	}
	_ = listener.Close()
}

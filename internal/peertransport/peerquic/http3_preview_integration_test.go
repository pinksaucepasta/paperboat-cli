package peerquic_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
	"github.com/quic-go/quic-go/http3"
)

func TestPreviewHTTP3StreamOutlivesSetupContext(t *testing.T) {
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientPacket, serverPacket := net.Pipe()
	listener, err := peerquic.Listen(serverPacket, serverTLS, peerquic.ClassPreview)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *peerquic.Session, 1)
	go func() {
		session, _ := listener.Accept(ctx)
		accepted <- session
	}()
	clientSession, err := peerquic.Dial(ctx, clientPacket, clientTLS, peerquic.ClassPreview)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	serverSession := <-accepted
	defer serverSession.Close()
	server := &http3.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(writer).Flush()
		_, _ = io.Copy(writer, request.Body)
	})}
	go server.ServeQUICConn(serverSession.Connection)
	defer server.Close()
	client := (&http3.Transport{}).NewClientConn(clientSession.Connection)
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	streamCtx, cancelStream := context.WithCancel(context.WithoutCancel(setupCtx))
	reader, writer := io.Pipe()
	request := (&http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: "private-preview.paperboat", Path: "/"}, Proto: peerpreview.HTTP3ConnectProtocol, Host: "private-preview.paperboat", Header: make(http.Header), Body: reader}).WithContext(streamCtx)
	response, err := client.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	cancelSetup()
	payload := []byte("bytes-after-setup")
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(response.Body, got); err != nil || string(got) != string(payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	cancelStream()
	_ = writer.Close()
	_ = response.Body.Close()
}

package peerquic_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestStreamRouterServesHealthWithoutConsumingApplicationStream(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte("application-stream-prefix-and-private-payload")
	application, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	healthDone := make(chan error, 1)
	go func() {
		var nonce [16]byte
		copy(nonce[:], "router-health-ok")
		_, err := client.HealthExchange(ctx, nonce)
		healthDone <- err
	}()
	routed, err := router.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(routed)
	if err != nil {
		t.Fatal(err)
	}
	if err := routed.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("received=%q", received)
	}
	if err := <-healthDone; err != nil {
		t.Fatal(err)
	}
	if err := router.WaitInitialHealth(ctx); err != nil {
		t.Fatal(err)
	}
	var secondNonce [16]byte
	copy(secondNonce[:], "router-health-2")
	if _, err := client.HealthExchange(ctx, secondNonce); err != nil {
		t.Fatal(err)
	}
	if err := router.WaitHealthExchanges(ctx, 2); err != nil {
		t.Fatal(err)
	}
}

func TestPrivatePreviewExtendedConnectWaitsForHTTP3Handoff(t *testing.T) {
	client, server, closePair := routerSessionPairForClass(t, peerquic.ClassPreview)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var nonce [16]byte
	copy(nonce[:], "preview-handoff")
	healthDone := make(chan error, 1)
	go func() { _, healthErr := client.HealthExchange(ctx, nonce); healthDone <- healthErr }()
	if err := router.WaitInitialHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-healthDone; err != nil {
		t.Fatal(err)
	}

	previewClient := (&http3.Transport{}).NewClientConn(client.Connection)
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	request := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: "private-preview.paperboat", Path: "/"},
		Proto:  peerpreview.HTTP3ConnectProtocol,
		Host:   "private-preview.paperboat",
		Header: make(http.Header),
	}).WithContext(requestCtx)
	responseDone := make(chan *http.Response, 1)
	requestErrors := make(chan error, 1)
	go func() {
		response, requestErr := previewClient.RoundTrip(request)
		if requestErr != nil {
			requestErrors <- requestErr
			return
		}
		responseDone <- response
	}()

	beforeHandoff, cancelBeforeHandoff := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelBeforeHandoff()
	if stream, acceptErr := router.Accept(beforeHandoff); !errors.Is(acceptErr, context.DeadlineExceeded) {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatalf("HTTP/3 request reached Paperboat router before handoff: %v", acceptErr)
	}
	if err := router.Handoff(); err != nil {
		t.Fatal(err)
	}
	previewServer := &http3.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Proto != peerpreview.HTTP3ConnectProtocol || request.URL.Path != "/" {
			http.Error(writer, "invalid preview request", http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- previewServer.ServeQUICConn(server.Connection) }()
	select {
	case response := <-responseDone:
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status=%s", response.Status)
		}
	case err := <-requestErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancelRequest()
	_ = client.Connection.CloseWithError(0, "complete")
	select {
	case <-serveDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestStreamRouterRoutesCandidateControlSeparately(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte("candidate-adopt-payload")
	control := make(chan []byte, 1)
	config := peerquic.DevelopmentStreamRouterConfig()
	config.CandidateControl = func(_ context.Context, stream *quic.Stream) error {
		value, err := io.ReadAll(stream)
		if err == nil {
			control <- value
		}
		return err
	}
	router, err := peerquic.NewStreamRouter(server, config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	stream, err := client.OpenCandidateControl(ctx, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-control:
		if !bytes.Equal(got, payload) {
			t.Fatalf("control payload=%q", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	application, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	if _, err := application.Write([]byte("ordinary")); err != nil {
		t.Fatal(err)
	}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	routed, err := router.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(routed)
	if err != nil || !bytes.Equal(got, []byte("ordinary")) {
		t.Fatalf("application=%q err=%v", got, err)
	}
}

func TestStreamRouterReturnsHealthStreamCreditWhileApplicationStreamIsOpen(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	application, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	if _, err := application.Write([]byte("application-stream-remains-open")); err != nil {
		t.Fatal(err)
	}
	routed, err := router.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer routed.Close()

	for sequence := range 80 {
		var nonce [16]byte
		nonce[0] = byte(sequence)
		if _, err := client.HealthExchange(ctx, nonce); err != nil {
			t.Fatalf("health exchange %d: %v", sequence+1, err)
		}
	}
	if err := router.WaitHealthExchanges(ctx, 64); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterFailsClosedOnMalformedReservedHealthFrame(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	malformed := make([]byte, 22)
	copy(malformed, []byte{'P', 'B', 'L', 'P', 99, 1})
	if _, err := stream.Write(malformed); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if _, err := router.Accept(ctx); !errors.Is(err, peerquic.ErrStreamRouterProtocol) {
		t.Fatalf("accept error=%v", err)
	}
	if err := router.Close(); !errors.Is(err, peerquic.ErrStreamRouterProtocol) {
		t.Fatalf("close error=%v", err)
	}
}

func TestStreamRouterKeepsSessionAfterCanceledHealthProbe(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{'P', 'B', 'L', 'P'}); err != nil {
		t.Fatal(err)
	}
	stream.CancelRead(quic.StreamErrorCode(0x5042))
	stream.CancelWrite(quic.StreamErrorCode(0x5042))
	_ = stream.Close()

	var nonce [16]byte
	copy(nonce[:], "after-canceled-probe")
	if _, err := client.HealthExchange(ctx, nonce); err != nil {
		t.Fatalf("health exchange after canceled probe: %v", err)
	}
	if err := router.WaitInitialHealth(ctx); err != nil {
		t.Fatalf("router closed after canceled probe: %v", err)
	}
}

func TestStreamRouterCloseInterruptsBlockedConsumerAccept(t *testing.T) {
	_, server, closePair := routerSessionPair(t)
	defer closePair()
	router, err := peerquic.NewStreamRouter(server, peerquic.DevelopmentStreamRouterConfig())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	healthDone := make(chan error, 1)
	go func() {
		_, err := router.Accept(context.Background())
		done <- err
	}()
	go func() { healthDone <- router.WaitInitialHealth(context.Background()) }()
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("accept error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("router close did not interrupt accept")
	}
	select {
	case err := <-healthDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("health readiness error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("router close did not interrupt health readiness")
	}
}

func TestStreamRouterClassifierLimitFailsConnection(t *testing.T) {
	client, server, closePair := routerSessionPair(t)
	defer closePair()
	config := peerquic.DevelopmentStreamRouterConfig()
	config.MaximumClassifiers = 1
	router, err := peerquic.NewStreamRouter(server, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte{'a'}); err != nil {
		t.Fatal(err)
	}
	second, err := client.Connection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write([]byte{'b'}); err != nil {
		t.Fatal(err)
	}
	if _, err := router.Accept(ctx); !errors.Is(err, peerquic.ErrStreamRouterLimit) {
		t.Fatalf("accept error=%v", err)
	}
	if err := router.Close(); !errors.Is(err, peerquic.ErrStreamRouterLimit) {
		t.Fatalf("close error=%v", err)
	}
}

func routerSessionPair(t *testing.T) (*peerquic.Session, *peerquic.Session, func()) {
	return routerSessionPairForClass(t, peerquic.ClassInteractive)
}

func routerSessionPairForClass(t *testing.T, class peerquic.Class) (*peerquic.Session, *peerquic.Session, func()) {
	t.Helper()
	clientTLS, serverTLS := probeTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.Listen(serverConn, serverTLS, class)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	accepted := make(chan *peerquic.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()
	client, err := peerquic.Dial(ctx, clientConn, clientTLS, class)
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *peerquic.Session
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		cancel()
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(ctx.Err())
	}
	return client, server, func() {
		cancel()
		_ = client.Close()
		_ = server.Close()
		_ = listener.Close()
	}
}

package relaycarrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestRelayQUICStreamReadDeadlineCancelsBlockedHTTP3Body(t *testing.T) {
	responseReader, responseWriter := io.Pipe()
	_, requestWriter := io.Pipe()
	stream := &relayQUICStream{
		reader: responseReader, writer: requestWriter,
		cancel: func() { _ = responseWriter.CloseWithError(context.Canceled) },
	}
	defer stream.Close()
	if err := stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline error=%v", err)
	}
}

func TestRelayQUICStreamCloseCancelsPendingHTTP3Body(t *testing.T) {
	responseReader, responseWriter := io.Pipe()
	_, requestWriter := io.Pipe()
	stream := &relayQUICStream{
		reader: responseReader, writer: requestWriter,
		cancel: func() { _ = responseWriter.CloseWithError(context.Canceled) },
	}
	done := make(chan error, 1)
	go func() { done <- stream.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("close error=%v", err)
		}
	case <-time.After(2 * relayQUICCloseGrace):
		t.Fatal("close blocked draining a pending HTTP/3 response body")
	}
}

func TestRelayQUICStreamCloseDrainsPeerFINBeforeCancel(t *testing.T) {
	responseReader, responseWriter := io.Pipe()
	requestReader, requestWriter := io.Pipe()
	stream := &relayQUICStream{
		reader: responseReader, writer: requestWriter,
		cancel: func() { _ = responseWriter.CloseWithError(context.Canceled) },
	}
	peerDone := make(chan error, 1)
	go func() {
		if _, err := io.ReadAll(requestReader); err != nil {
			peerDone <- err
			return
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := responseWriter.Write([]byte("peer-final")); err != nil {
			peerDone <- err
			return
		}
		peerDone <- responseWriter.Close()
	}()

	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-peerDone; err != nil {
		t.Fatalf("peer final bytes were reset: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type pairedRoundTripper struct {
	mu       sync.Mutex
	requests map[string]io.ReadCloser
	count    int
	ready    chan struct{}
}

func newPairedRoundTripper() *pairedRoundTripper {
	return &pairedRoundTripper{requests: make(map[string]io.ReadCloser), ready: make(chan struct{})}
}

func (p *pairedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	role := request.Header.Get("X-Paperboat-Relay-Role")
	peer := "responder"
	if role == "responder" {
		peer = "initiator"
	}
	preface := make([]byte, len(relayQUICRequestPreface))
	if _, err := io.ReadFull(request.Body, preface); err != nil || !bytes.Equal(preface, relayQUICRequestPreface[:]) {
		return nil, errors.New("invalid relay request preface")
	}
	reader, writer := io.Pipe()
	go func() {
		_, err := io.Copy(writer, request.Body)
		_ = writer.CloseWithError(err)
	}()
	p.mu.Lock()
	p.requests[role] = reader
	p.count++
	if p.count == 2 {
		close(p.ready)
	}
	p.mu.Unlock()
	<-p.ready
	p.mu.Lock()
	peerBody := p.requests[peer]
	p.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, ProtoMajor: 3, Body: peerBody, Header: make(http.Header)}, nil
}

func TestRelayQUICUsesOnePersistentAuthenticatedHTTP3Attachment(t *testing.T) {
	handle := [16]byte{7}
	transport := newPairedRoundTripper()
	dial := func(role string) (*Connection, error) {
		return DialQUIC(context.Background(), QUICDialConfig{URL: "https://relay.example.test/v1/peer-relay", Credential: "route.token.signature", EndpointID: "endpoint_" + role, Role: role, StreamHandle: handle, TLS: &tls.Config{MinVersion: tls.VersionTLS13}, HTTPClient: &http.Client{Transport: transport}, MaximumDeadline: time.Minute, Carrier: DevelopmentConfig()})
	}
	type outcome struct {
		connection *Connection
		err        error
	}
	initiatorResult, responderResult := make(chan outcome, 1), make(chan outcome, 1)
	go func() { connection, err := dial("initiator"); initiatorResult <- outcome{connection, err} }()
	go func() { connection, err := dial("responder"); responderResult <- outcome{connection, err} }()
	initiator, responder := <-initiatorResult, <-responderResult
	if initiator.err != nil || responder.err != nil {
		t.Fatalf("initiator=%v responder=%v", initiator.err, responder.err)
	}
	defer initiator.connection.Close()
	defer responder.connection.Close()
	for _, payload := range []string{"first-logical-stream", "second-logical-stream"} {
		accepted := make(chan io.ReadWriteCloser, 1)
		go func() { stream, _ := responder.connection.AcceptStream(context.Background()); accepted <- stream }()
		stream, err := initiator.connection.OpenStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		peer := <-accepted
		if peer == nil {
			t.Fatal("responder did not accept logical stream")
		}
		go func() { _, _ = stream.Write([]byte(payload)) }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, got); err != nil || string(got) != payload {
			t.Fatalf("payload=%q error=%v", got, err)
		}
		_ = stream.Close()
		_ = peer.Close()
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.count != 2 {
		t.Fatalf("HTTP/3 attachment requests=%d", transport.count)
	}
}

func TestRelayQUICRejectsMissingPersistentHandleAndNonHTTP3(t *testing.T) {
	base := QUICDialConfig{URL: "https://relay.example.test/v1/peer-relay", Credential: "route.token.signature", EndpointID: "endpoint_cli", Role: "initiator", TLS: &tls.Config{MinVersion: tls.VersionTLS13}, HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ProtoMajor: 2, Body: http.NoBody}, nil
	})}, MaximumDeadline: time.Minute, Carrier: DevelopmentConfig()}
	if _, err := DialQUIC(context.Background(), base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing handle error=%v", err)
	}
	base.StreamHandle = [16]byte{1}
	connection, err := DialQUIC(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if stream, err := connection.OpenStream(ctx); err == nil {
		_ = stream.Close()
		t.Fatal("non-HTTP/3 relay response carried a logical stream")
	}
}

func TestRelayQUICCarriesFullDuplexBytesOverRealHTTP3(t *testing.T) {
	clientTLS, serverTLS := relayTLSConfigs(t)
	clientTLS.NextProtos = []string{http3.NextProtoH3}
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	serverTLS.ClientAuth = tls.NoClientCert
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 3 || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer route.token.signature" || request.Header.Get("X-Paperboat-Relay-Carrier") != "HTTP/3.0" || request.Header.Get("X-Paperboat-Stream-Handle") == "" {
			t.Errorf("proto=%s method=%s headers=%v", request.Proto, request.Method, request.Header)
			http.Error(writer, "invalid", http.StatusUnauthorized)
			return
		}
		preface := make([]byte, len(relayQUICRequestPreface))
		if _, err := io.ReadFull(request.Body, preface); err != nil || !bytes.Equal(preface, relayQUICRequestPreface[:]) {
			t.Errorf("relay request preface=%x error=%v", preface, err)
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(writer).Flush()
		_, _ = io.Copy(writer, request.Body)
	})}
	served := make(chan error, 1)
	go func() { served <- server.Serve(packet) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packet.Close()
		<-served
	})
	transport := &http3.Transport{TLSClientConfig: clientTLS}
	defer transport.Close()
	ctx, cancel := context.WithCancel(context.Background())
	attachment := &relayQUICMux{ctx: ctx, cancel: cancel, client: &http.Client{Transport: transport}, url: "https://" + packet.LocalAddr().String() + "/v1/peer-relay", credential: "route.token.signature", endpointID: "endpoint_cli", role: "initiator", closeTransport: transport.Close}
	defer attachment.Close()
	stream, err := attachment.open(context.Background(), [16]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload := []byte("real-http3-relay-record")
	written := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write(payload)
		written <- writeErr
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != string(payload) {
		t.Fatalf("payload=%q error=%v", got, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

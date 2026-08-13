package relaycarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

func TestRelayQUICNoiseInteroperability(t *testing.T) {
	clientSession, serverSession := quicPair(t)
	config := DevelopmentConfig()
	client, err := NewRelayQUIC(clientSession, config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewRelayQUIC(serverSession, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	initiator, responder, handle, prologue := testIdentities(t, relaynoise.CarrierRelayQUIC)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		stream *SecureStream
		err    error
	}
	accepted := make(chan result, 1)
	go func() {
		stream, _, err := server.Accept(ctx, ResponderConfig{
			LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle,
			Authorize: func(context.Context, []byte) ([]byte, error) { return []byte("accepted"), nil },
		})
		accepted <- result{stream: stream, err: err}
	}()
	clientStream, response, err := client.Initiate(ctx, InitiatorConfig{
		LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle, InitialPayload: []byte("request"),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-accepted
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	defer clientStream.Close()
	defer serverResult.stream.Close()
	if string(response) != "accepted" {
		t.Fatalf("response=%q", response)
	}
	if err := clientStream.Send(ctx, []byte("private-quic-record"), true); err != nil {
		t.Fatal(err)
	}
	plaintext, closed, err := serverResult.stream.Receive(ctx)
	if err != nil || !closed || string(plaintext) != "private-quic-record" {
		t.Fatalf("plaintext=%q closed=%v err=%v", plaintext, closed, err)
	}
}

func TestWSSNoiseInteroperabilityAndWirePrivacy(t *testing.T) {
	client, server, capture := wssPair(t, 4)
	initiator, responder, handle, prologue := testIdentities(t, relaynoise.CarrierWSS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	requestCanary := []byte("private-request-canary")
	responseCanary := []byte("private-response-canary")
	type accepted struct {
		stream  *SecureStream
		request []byte
		err     error
	}
	acceptedResult := make(chan accepted, 1)
	go func() {
		stream, request, err := server.Accept(ctx, ResponderConfig{
			LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle,
			Authorize: func(_ context.Context, request []byte) ([]byte, error) {
				if !bytes.Equal(request, requestCanary) {
					return nil, errors.New("unexpected request")
				}
				return responseCanary, nil
			},
		})
		acceptedResult <- accepted{stream: stream, request: request, err: err}
	}()
	initiated, response, err := client.Initiate(ctx, InitiatorConfig{
		LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle, InitialPayload: requestCanary,
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptedValue := <-acceptedResult
	if acceptedValue.err != nil {
		t.Fatal(acceptedValue.err)
	}
	defer initiated.Close()
	defer acceptedValue.stream.Close()
	if !bytes.Equal(response, responseCanary) || !bytes.Equal(acceptedValue.request, requestCanary) {
		t.Fatalf("request=%q response=%q", acceptedValue.request, response)
	}

	clientCanary := []byte("private-client-record-canary")
	if err := initiated.Send(ctx, clientCanary, false); err != nil {
		t.Fatal(err)
	}
	got, closed, err := acceptedValue.stream.Receive(ctx)
	if err != nil || closed || !bytes.Equal(got, clientCanary) {
		t.Fatalf("received=%q closed=%v err=%v", got, closed, err)
	}
	serverCanary := []byte("private-server-record-canary")
	if err := acceptedValue.stream.Send(ctx, serverCanary, true); err != nil {
		t.Fatal(err)
	}
	got, closed, err = initiated.Receive(ctx)
	if err != nil || !closed || !bytes.Equal(got, serverCanary) {
		t.Fatalf("received=%q closed=%v err=%v", got, closed, err)
	}
	for _, canary := range [][]byte{requestCanary, responseCanary, clientCanary, serverCanary} {
		if bytes.Contains(capture.Bytes(), canary) {
			t.Fatalf("private content visible on WSS carrier: %q", canary)
		}
	}
}

func TestWSSRoutesConcurrentNoiseStreamsByHandle(t *testing.T) {
	client, server, _ := wssPair(t, 4)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	initiator, responder, healthHandle, healthPrologue := testIdentities(t, relaynoise.CarrierWSS)
	applicationHandle := healthHandle
	applicationHandle[15]++
	applicationPrologue := healthPrologue
	healthPrologue.StreamID = "native-health"
	applicationPrologue.StreamID = "authorized-stream"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type acceptedResult struct {
		name    string
		payload string
		err     error
	}
	accepted := make(chan acceptedResult, 2)
	accept := func(name string, handle [16]byte, prologue relaynoise.Prologue) {
		stream, payload, err := server.Accept(ctx, ResponderConfig{
			LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle,
			Authorize: func(_ context.Context, request []byte) ([]byte, error) {
				return append([]byte("accepted-"), request...), nil
			},
		})
		if stream != nil {
			_ = stream.Close()
		}
		accepted <- acceptedResult{name: name, payload: string(payload), err: err}
	}
	go accept("health", healthHandle, healthPrologue)
	go accept("application", applicationHandle, applicationPrologue)

	serverMux := server.mux.(*yamuxMux)
	for {
		serverMux.acceptMu.Lock()
		ready := len(serverMux.waiters[healthHandle]) == 1 && len(serverMux.waiters[applicationHandle]) == 1
		serverMux.acceptMu.Unlock()
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("concurrent handled accepts were not registered")
		default:
			runtime.Gosched()
		}
	}

	for _, request := range []struct {
		handle   [16]byte
		prologue relaynoise.Prologue
		payload  string
	}{{applicationHandle, applicationPrologue, "application"}, {healthHandle, healthPrologue, "health"}} {
		stream, response, err := client.Initiate(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: request.prologue, Handle: request.handle, InitialPayload: []byte(request.payload)})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(response), "accepted-"+request.payload; got != want {
			t.Fatalf("response=%q want=%q", got, want)
		}
		_ = stream.Close()
	}

	seen := make(map[string]string, 2)
	for range 2 {
		result := <-accepted
		if result.err != nil {
			t.Fatal(result.err)
		}
		seen[result.name] = result.payload
	}
	if seen["health"] != "health" || seen["application"] != "application" {
		t.Fatalf("routed payloads=%v", seen)
	}
}

func TestWSSAuthorizationFailureClosesStreamAndReleasesPermit(t *testing.T) {
	client, server, _ := wssPair(t, 1)
	initiator, responder, handle, prologue := testIdentities(t, relaynoise.CarrierWSS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rejected := errors.New("revoked")
	serverResult := make(chan error, 1)
	go func() {
		_, _, err := server.Accept(ctx, ResponderConfig{
			LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle,
			Authorize: func(context.Context, []byte) ([]byte, error) { return nil, rejected },
		})
		serverResult <- err
	}()
	if _, _, err := client.Initiate(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle}); err == nil {
		t.Fatal("initiator accepted rejected stream")
	}
	if err := <-serverResult; !errors.Is(err, rejected) {
		t.Fatalf("server error=%v", err)
	}

	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("permit was not released: %v", err)
	}
	_ = stream.Close()
}

func TestWSSStreamLimitAndCanceledAccept(t *testing.T) {
	client, server, _ := wssPair(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan struct {
		stream interface{ Close() error }
		err    error
	}, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		accepted <- struct {
			stream interface{ Close() error }
			err    error
		}{stream, err}
	}()
	first, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serverStream := <-accepted
	if serverStream.err != nil {
		t.Fatal(serverStream.err)
	}
	if _, err := client.OpenStream(ctx); !errors.Is(err, ErrLimit) {
		t.Fatalf("second stream error=%v", err)
	}
	_ = first.Close()
	_ = serverStream.stream.Close()

	acceptCtx, stopAccept := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := server.AcceptStream(acceptCtx); result <- err }()
	stopAccept()
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("accept error=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled accept did not exit")
	}
	if server.State() != connectionmanager.StateFailed {
		t.Fatalf("server state=%v", server.State())
	}
}

func TestHandshakeDeadlineJoinsCancellationBeforeRestoring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	interruptStarted := make(chan struct{})
	allowInterrupt := make(chan struct{})
	var mu sync.Mutex
	var deadlines []time.Time
	setDeadline := func(deadline time.Time) error {
		mu.Lock()
		deadlines = append(deadlines, deadline)
		mu.Unlock()
		if !deadline.IsZero() {
			close(interruptStarted)
			<-allowInterrupt
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- withHandshakeDeadline(ctx, setDeadline, func() error {
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	cancel()
	<-interruptStarted
	select {
	case err := <-done:
		t.Fatalf("deadline helper returned before interrupt completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowInterrupt)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("deadline helper error=%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deadlines) != 2 || deadlines[0].IsZero() || !deadlines[1].IsZero() {
		t.Fatalf("deadlines=%v", deadlines)
	}
}

func TestHandshakeDeadlineReturnsRestorationFailure(t *testing.T) {
	want := errors.New("restore deadline")
	err := withHandshakeDeadline(context.Background(), func(deadline time.Time) error {
		if deadline.IsZero() {
			return want
		}
		return nil
	}, func() error { return nil })
	if !errors.Is(err, want) {
		t.Fatalf("deadline helper error=%v", err)
	}
}

type wireCapture struct {
	sync.Mutex
	bytes.Buffer
}

func (c *wireCapture) append(value []byte) {
	c.Lock()
	defer c.Unlock()
	_, _ = c.Buffer.Write(value)
}

func (c *wireCapture) Bytes() []byte {
	c.Lock()
	defer c.Unlock()
	return bytes.Clone(c.Buffer.Bytes())
}

type capturedConn struct {
	net.Conn
	capture *wireCapture
}

func (c *capturedConn) Write(value []byte) (int, error) {
	n, err := c.Conn.Write(value)
	c.capture.append(value[:n])
	return n, err
}

func wssPair(t *testing.T, maximumStreams int) (*Connection, *Connection, *wireCapture) {
	t.Helper()
	left, right := net.Pipe()
	capture := &wireCapture{}
	config := DevelopmentConfig()
	config.MaximumStreams = maximumStreams
	config.AcceptBacklog = maximumStreams
	client, err := newWSS(&capturedConn{Conn: left, capture: capture}, config, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWSS(&capturedConn{Conn: right, capture: capture}, config, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server, capture
}

func testIdentities(t *testing.T, carrier relaynoise.Carrier) (noise.DHKey, noise.DHKey, [16]byte, relaynoise.Prologue) {
	t.Helper()
	initiator, err := relaynoise.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	responder, err := relaynoise.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	var handle [16]byte
	copy(handle[:], bytes.Repeat([]byte{3}, len(handle)))
	contextValue := peercontext.Context{
		AccountID: "account_01", UserID: "user_01", DeviceID: "cli_01", MachineID: "machine_01",
		HostGeneration: 2, AuthorizationGeneration: 4, IntentID: "intent_01", OperationID: "operation_01",
		Consumer: "terminal", InitiatorRole: "cli", ResponderRole: "machine", AttemptGeneration: 3,
	}
	copy(contextValue.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(contextValue.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return initiator, responder, handle, relaynoise.Prologue{Context: contextValue, Carrier: carrier, StreamID: "stream_01"}
}

func public32(key noise.DHKey) [32]byte {
	var result [32]byte
	copy(result[:], key.Public)
	return result
}

func quicPair(t *testing.T) (*peerquic.Session, *peerquic.Session) {
	t.Helper()
	clientTLS, serverTLS := relayTLSConfigs(t)
	clientConn, serverConn := net.Pipe()
	listener, err := peerquic.Listen(serverConn, serverTLS, peerquic.ClassPreview)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
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
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErrors:
		_ = client.Close()
		t.Fatal(err)
	case <-ctx.Done():
		_ = client.Close()
		t.Fatal(ctx.Err())
	}
	return nil, nil
}

func relayTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	issue := func(serial int64, commonName string) tls.Certificate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	}
	verify := func(tls.ConnectionState) error { return nil }
	client := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{peerquic.ALPN}, InsecureSkipVerify: true,
		VerifyConnection: verify, Certificates: []tls.Certificate{issue(1, "relay-client")},
	}
	server := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{peerquic.ALPN}, InsecureSkipVerify: true,
		VerifyConnection: verify, ClientAuth: tls.RequireAnyClientCert, Certificates: []tls.Certificate{issue(2, "relay-server")},
	}
	return client, server
}

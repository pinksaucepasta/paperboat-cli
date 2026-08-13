package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

type previewRoundTripFunc func(*http.Request) (*http.Response, error)

func (f previewRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func consumePublicPreviewPreface(t *testing.T, request *http.Request) {
	t.Helper()
	preface := make([]byte, len(publicPreviewRelayPreface))
	if _, err := io.ReadFull(request.Body, preface); err != nil || !bytes.Equal(preface, publicPreviewRelayPreface[:]) {
		t.Errorf("public preview preface=%q error=%v", preface, err)
	}
	startup := make([]byte, 1)
	if _, err := io.ReadFull(request.Body, startup); err != nil || startup[0] != publicPreviewStartupMarker {
		t.Errorf("public preview startup=%v error=%v", startup, err)
	}
}

func previewAdmission() Admission {
	return Admission{OperationID: "operation_preview_1", JTI: "jti_1", Credential: strings.Repeat("c", 40), EnvironmentID: "env", MachineID: "machine", ConnectorID: "preview", Generation: 1, EdgePool: "default", EdgeNodeID: "edge_1", RelayHTTPEndpoint: "https://relay.test", Endpoint: EdgeEndpoint{Host: "edge.test", Port: 7000}, Routes: []RouteHandoff{{RouteID: "route_1", Revision: 1, Kind: "preview_public_https_wss", PublicHost: "preview.preview.test", ProxyName: "route_1", LocalTarget: RouteTarget{Host: "127.0.0.1", Port: 3000}}}, ProtocolVersion: "1.0", ExpiresAt: time.Now().Add(time.Minute), FileTransferPolicy: testFileTransferPolicy()}
}

func TestPublicPreviewDialerUsesHTTP3WithoutWaitingForHTTP2(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	var h2 atomic.Int32
	dialer, err := NewPublicPreviewDialer(PublicPreviewDialerConfig{HTTP3: previewRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://relay.test/v1/public-preview-relay" || request.Header.Get("X-Paperboat-Connector-Admission") == "" {
			t.Fatalf("request=%+v", request)
		}
		if request.Header.Get("X-Paperboat-Relay-Carrier") != "HTTP/3.0" {
			t.Fatalf("carrier=%q", request.Header.Get("X-Paperboat-Relay-Carrier"))
		}
		consumePublicPreviewPreface(t, request)
		return &http.Response{StatusCode: http.StatusOK, Body: client}, nil
	}), HTTP2: previewRoundTripFunc(func(*http.Request) (*http.Response, error) { h2.Add(1); return nil, errors.New("unexpected") })})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.Dial(context.Background(), QUIC, previewAdmission())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if h2.Load() != 0 || connection.(*publicPreviewConnection).protocol != PublicPreviewHTTP3 {
		t.Fatalf("h2=%d protocol=%s", h2.Load(), connection.(*publicPreviewConnection).protocol)
	}
}

func TestPublicPreviewDialerMakesPrefaceSynchronouslyAvailableToHTTP3(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dialer, err := NewPublicPreviewDialer(PublicPreviewDialerConfig{HTTP3: previewRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		// HTTP/3 starts request transmission by reading the body in the RoundTrip
		// call. The protocol preface must not depend on a separate pipe writer.
		consumePublicPreviewPreface(t, request)
		return &http.Response{StatusCode: http.StatusOK, Body: client}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialer.Dial(context.Background(), QUIC, previewAdmission())
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
}

func TestPublicPreviewDialerFallsBackOnlyFromHTTP3TransportFailure(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dialer, _ := NewPublicPreviewDialer(PublicPreviewDialerConfig{HTTP3: previewRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "udp", Err: errors.New("udp blocked")}
	}), HTTP2: previewRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		consumePublicPreviewPreface(t, request)
		return &http.Response{StatusCode: http.StatusOK, Body: client}, nil
	})})
	connection, err := dialer.Dial(context.Background(), QUIC, previewAdmission())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.(*publicPreviewConnection).protocol != PublicPreviewHTTP2 {
		t.Fatalf("protocol=%s", connection.(*publicPreviewConnection).protocol)
	}

	var h2 atomic.Int32
	dialer, _ = NewPublicPreviewDialer(PublicPreviewDialerConfig{HTTP3: previewRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	}), HTTP2: previewRoundTripFunc(func(*http.Request) (*http.Response, error) { h2.Add(1); return nil, errors.New("must not run") })})
	if _, err := dialer.Dial(context.Background(), QUIC, previewAdmission()); !errors.Is(err, ErrAdmissionInvalid) || h2.Load() != 0 {
		t.Fatalf("err=%v h2=%d", err, h2.Load())
	}
}

func TestPublicPreviewConnectionMultiplexesConcurrentOpaqueStreams(t *testing.T) {
	left, right := net.Pipe()
	config := yamux.DefaultConfig()
	clientMux, err := yamux.Client(left, config)
	if err != nil {
		t.Fatal(err)
	}
	serverMux, err := yamux.Server(right, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientMux.Close(); _ = serverMux.Close() })
	go func() {
		for {
			accepted, acceptErr := clientMux.AcceptStream()
			if acceptErr != nil {
				return
			}
			go func() { data := make([]byte, 64); count, _ := accepted.Read(data); _, _ = accepted.Write(data[:count]) }()
		}
	}()
	for _, payload := range []string{"first-binary-\x00-payload", "second-concurrent-payload"} {
		payload := payload
		t.Run(payload[:5], func(t *testing.T) {
			t.Parallel()
			stream, err := serverMux.OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := stream.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			echoed := make([]byte, len(payload))
			_, err = io.ReadFull(stream, echoed)
			if err != nil || string(echoed) != payload {
				t.Fatalf("echo=%q err=%v", echoed, err)
			}
		})
	}
}

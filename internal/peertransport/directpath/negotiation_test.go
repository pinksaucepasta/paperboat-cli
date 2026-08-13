package directpath

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/signaling"
	"github.com/pion/ice/v4"
)

func TestNegotiateExchangesCandidatesAndNominatesBothRoles(t *testing.T) {
	leftConfig := assemblyConfig("ufragA1", "pppppppppppppppppppppp", []byte("negotiation-key-0123456789012345"))
	leftConfig.AttemptGeneration, leftConfig.NetworkGeneration = 2, 4
	left, err := Open(context.Background(), leftConfig)
	if err != nil {
		t.Fatal(err)
	}
	rightConfig := assemblyConfig("ufragB1", "qqqqqqqqqqqqqqqqqqqqqq", []byte("negotiation-key-0123456789012345"))
	rightConfig.AttemptGeneration, rightConfig.NetworkGeneration = 2, 4
	right, err := Open(context.Background(), rightConfig)
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	leftTransport, rightTransport := newTransportPair()
	leftBinding := signaling.Binding{IntentID: "intent_negotiation", AttemptGeneration: 2, NetworkGeneration: 4, Role: signaling.RoleControlling}
	rightBinding := signaling.Binding{IntentID: "intent_negotiation", AttemptGeneration: 2, NetworkGeneration: 4, Role: signaling.RoleControlled}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		conn    *ice.Conn
		connErr error
		remote  string
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		connection, connectErr := Negotiate(ctx, NegotiationConfig{Assembly: left, Transport: leftTransport, LocalBinding: leftBinding, RemoteBinding: rightBinding, LocalUfrag: "ufragA1", LocalPassword: "pppppppppppppppppppppp"})
		if connection != nil {
			results <- result{conn: connection, remote: connection.RemoteAddr().String(), connErr: connectErr}
			return
		}
		results <- result{connErr: connectErr}
	}()
	go func() {
		defer wait.Done()
		connection, connectErr := Negotiate(ctx, NegotiationConfig{Assembly: right, Transport: rightTransport, LocalBinding: rightBinding, RemoteBinding: leftBinding, LocalUfrag: "ufragB1", LocalPassword: "qqqqqqqqqqqqqqqqqqqqqq"})
		if connection != nil {
			results <- result{conn: connection, remote: connection.RemoteAddr().String(), connErr: connectErr}
			return
		}
		results <- result{connErr: connectErr}
	}()
	wait.Wait()
	close(results)
	for outcome := range results {
		if outcome.conn != nil {
			connection := outcome.conn
			t.Cleanup(func() { _ = connection.Close() })
		}
		if outcome.connErr != nil || outcome.remote == "" {
			t.Fatalf("negotiation remote=%q error=%v", outcome.remote, outcome.connErr)
		}
	}
}

func TestNegotiateKeepsSignalingOpenForPeerNominationAcknowledgement(t *testing.T) {
	leftConfig := assemblyConfig("ufragA1", "pppppppppppppppppppppp", []byte("negotiation-key-0123456789012345"))
	left, err := Open(context.Background(), leftConfig)
	if err != nil {
		t.Fatal(err)
	}
	rightConfig := assemblyConfig("ufragB1", "qqqqqqqqqqqqqqqqqqqqqq", []byte("negotiation-key-0123456789012345"))
	right, err := Open(context.Background(), rightConfig)
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	leftTransport, rawRightTransport := newTransportPair()
	leftBinding := signaling.Binding{IntentID: "intent_ack", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling}
	rightBinding := signaling.Binding{IntentID: "intent_ack", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlled}
	releaseReady := make(chan struct{})
	readyBlocked := make(chan struct{})
	rightTransport := &readyBlockingTransport{SignalingTransport: rawRightTransport, binding: rightBinding, release: releaseReady, blocked: readyBlocked}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		connection, negotiateErr := Negotiate(ctx, NegotiationConfig{Assembly: left, Transport: leftTransport, LocalBinding: leftBinding, RemoteBinding: rightBinding, LocalUfrag: "ufragA1", LocalPassword: "pppppppppppppppppppppp"})
		if connection != nil {
			defer connection.Close()
		}
		results <- negotiateErr
	}()
	go func() {
		connection, negotiateErr := Negotiate(ctx, NegotiationConfig{Assembly: right, Transport: rightTransport, LocalBinding: rightBinding, RemoteBinding: leftBinding, LocalUfrag: "ufragB1", LocalPassword: "qqqqqqqqqqqqqqqqqqqqqq"})
		if connection != nil {
			defer connection.Close()
		}
		results <- negotiateErr
	}()
	select {
	case <-readyBlocked:
	case <-ctx.Done():
		t.Fatal("peer never reached local nomination")
	}
	select {
	case <-results:
		t.Fatal("negotiation returned before peer nomination acknowledgement")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-leftTransport.closed:
		t.Fatal("signaling closed before peer acknowledgement")
	default:
	}
	close(releaseReady)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestNegotiateRejectsMismatchedAttemptBeforeOpeningTransport(t *testing.T) {
	assembly, err := Open(context.Background(), assemblyConfig("ufragA1", "pppppppppppppppppppppp", []byte("negotiation-key-0123456789012345")))
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{}
	_, err = Negotiate(context.Background(), NegotiationConfig{
		Assembly: assembly, Transport: transport,
		LocalBinding:  signaling.Binding{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling},
		RemoteBinding: signaling.Binding{IntentID: "intent", AttemptGeneration: 2, NetworkGeneration: 1, Role: signaling.RoleControlled},
		LocalUfrag:    "ufragA1", LocalPassword: "pppppppppppppppppppppp",
	})
	if !errors.Is(err, ErrNegotiationInvalid) || !transport.closed {
		t.Fatalf("err=%v closed=%t", err, transport.closed)
	}
	if err := assembly.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNegotiateRejectsTypedNilTransportAndRetainsCloseFailure(t *testing.T) {
	openAssembly := func() *Assembly {
		assembly, err := Open(context.Background(), assemblyConfig("ufragA1", "pppppppppppppppppppppp", []byte("negotiation-key-0123456789012345")))
		if err != nil {
			t.Fatal(err)
		}
		return assembly
	}
	binding := signaling.Binding{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlling}
	remote := signaling.Binding{IntentID: "intent", AttemptGeneration: 1, NetworkGeneration: 1, Role: signaling.RoleControlled}
	var typedNil *channelTransport
	assembly := openAssembly()
	if _, err := Negotiate(context.Background(), NegotiationConfig{Assembly: assembly, Transport: typedNil, LocalBinding: binding, RemoteBinding: remote, LocalUfrag: "ufragA1", LocalPassword: "pppppppppppppppppppppp"}); !errors.Is(err, ErrNegotiationInvalid) {
		t.Fatalf("typed nil error=%v", err)
	}
	closeWant := errors.New("signaling close failed")
	receiveWant := errors.New("signaling receive failed")
	assembly = openAssembly()
	transport := &failingTransport{closed: make(chan struct{}), receiveErr: receiveWant, closeErr: closeWant}
	_, err := Negotiate(context.Background(), NegotiationConfig{Assembly: assembly, Transport: transport, LocalBinding: binding, RemoteBinding: remote, LocalUfrag: "ufragA1", LocalPassword: "pppppppppppppppppppppp"})
	if !errors.Is(err, receiveWant) || !errors.Is(err, closeWant) || assembly.Port() != 0 {
		t.Fatalf("error=%v port=%d", err, assembly.Port())
	}
}

type channelTransport struct {
	send      chan<- []byte
	receive   <-chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newTransportPair() (*channelTransport, *channelTransport) {
	leftToRight := make(chan []byte, 256)
	rightToLeft := make(chan []byte, 256)
	return &channelTransport{send: leftToRight, receive: rightToLeft, closed: make(chan struct{})}, &channelTransport{send: rightToLeft, receive: leftToRight, closed: make(chan struct{})}
}

func (t *channelTransport) Send(ctx context.Context, value []byte) error {
	copyValue := append([]byte(nil), value...)
	select {
	case t.send <- copyValue:
		return nil
	case <-t.closed:
		return context.Canceled
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *channelTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case value := <-t.receive:
		return value, nil
	case <-t.closed:
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *channelTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

type recordingTransport struct{ closed bool }

func (t *recordingTransport) Send(context.Context, []byte) error      { return nil }
func (t *recordingTransport) Receive(context.Context) ([]byte, error) { return nil, context.Canceled }
func (t *recordingTransport) Close() error                            { t.closed = true; return nil }

type failingTransport struct {
	closed     chan struct{}
	closeOnce  sync.Once
	receiveErr error
	closeErr   error
}

type readyBlockingTransport struct {
	SignalingTransport
	binding signaling.Binding
	release <-chan struct{}
	blocked chan<- struct{}
	once    sync.Once
}

func (t *readyBlockingTransport) Send(ctx context.Context, raw []byte) error {
	message, err := signaling.Decode(raw, t.binding)
	if err != nil {
		return err
	}
	if message.Kind == signaling.KindReady {
		t.once.Do(func() { close(t.blocked) })
		select {
		case <-t.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return t.SignalingTransport.Send(ctx, raw)
}

func (t *failingTransport) Send(ctx context.Context, _ []byte) error {
	select {
	case <-t.closed:
		return context.Canceled
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *failingTransport) Receive(context.Context) ([]byte, error) { return nil, t.receiveErr }
func (t *failingTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return t.closeErr
}

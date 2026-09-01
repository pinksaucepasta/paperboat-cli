package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testDataCarrierConfig() DataCarrierConfig {
	return DataCarrierConfig{
		MaximumStreams:       2,
		AcceptBacklog:        2,
		QueueDepth:           2,
		StreamWindow:         256 << 10,
		KeepAliveInterval:    20 * time.Millisecond,
		ConnectionWriteLimit: time.Second,
		StreamOpenLimit:      time.Second,
		StreamCloseLimit:     time.Second,
	}
}

func testDataCarrierIdentity() DataCarrierIdentity {
	return DataCarrierIdentity{AccountID: "account-a", HostID: "host-a", TunnelID: "tunnel-a", ConnectorID: "connector-a", SessionID: "session-a", ProcessGeneration: 7, Generation: 11}
}

func testDataCarrierStreamOpen(routeID, requestID string) StreamOpen {
	identity := testDataCarrierIdentity()
	return StreamOpen{Protocol: "paperboat.connector", Version: "1.0", AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: routeID, RequestID: requestID, Kind: "http"}
}

func TestDataCarrierStreamRoundTripAndLimit(t *testing.T) {
	config := testDataCarrierConfig()
	config.MaximumStreams = 1
	config.AcceptBacklog = 1
	config.QueueDepth = 1
	client, server := dataCarrierPair(t, config)

	stream, err := client.OpenStream(context.Background(), testDataCarrierStreamOpen("route-a", "request-a"))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()
	serverStream, _, err := server.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	defer serverStream.Close()
	if _, err := client.OpenStream(context.Background(), testDataCarrierStreamOpen("route-a", "request-b")); !errors.Is(err, ErrDataCarrierLimit) {
		t.Fatalf("second stream error = %v, want %v", err, ErrDataCarrierLimit)
	}

	payload := bytes.Repeat([]byte("streaming-body-"), 64*1024)
	readDone := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, serverStream)
		readDone <- n
	}()
	n, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("write body: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("write bytes = %d, want %d", n, len(payload))
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close client stream: %v", err)
	}
	select {
	case got := <-readDone:
		if got != int64(len(payload)) {
			t.Fatalf("read bytes = %d, want %d", got, len(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading streaming body")
	}
	if err := serverStream.Close(); err != nil {
		t.Fatalf("close server stream: %v", err)
	}
	if !waitForDataCarrier(func() bool { return client.ActiveStreams() == 0 && server.ActiveStreams() == 0 }) {
		t.Fatalf("stream permits were not released: client=%d server=%d", client.ActiveStreams(), server.ActiveStreams())
	}
}

func TestDataCarrierContextCancelsStream(t *testing.T) {
	client, server := dataCarrierPair(t, testDataCarrierConfig())
	streamContext, cancel := context.WithCancel(context.Background())
	stream, err := client.OpenStream(streamContext, testDataCarrierStreamOpen("route-a", "request-cancel"))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	serverStream, _, err := server.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	defer serverStream.Close()
	cancel()
	if !waitForDataCarrier(func() bool { return client.ActiveStreams() == 0 }) {
		t.Fatalf("context cancellation did not release client stream")
	}
	if _, err := stream.Write([]byte("after cancellation")); err == nil {
		t.Fatal("write succeeded after stream context cancellation")
	}
	_ = stream.Close()
}

func TestDataCarrierAcceptCancellationLeavesCarrierUsable(t *testing.T) {
	client, server := dataCarrierPair(t, testDataCarrierConfig())
	acceptContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := server.AcceptStream(acceptContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("accept error = %v, want deadline exceeded", err)
	}
	stream, err := client.OpenStream(context.Background(), testDataCarrierStreamOpen("route-a", "request-after-cancel"))
	if err != nil {
		t.Fatalf("open after canceled accept: %v", err)
	}
	defer stream.Close()
	accepted, _, err := server.AcceptStream(context.Background())
	if err != nil {
		t.Fatalf("accept after canceled accept: %v", err)
	}
	_ = accepted.Close()
}

func TestDataCarrierPoolFallbackAndLifecycle(t *testing.T) {
	config := testDataCarrierConfig()
	config.MaximumStreams = 4
	config.AcceptBacklog = 4
	poolConfig := DataCarrierPoolConfig{
		MaximumCarriers: 2,
		QueueDepth:      2,
		Preferred:       QUIC,
		Fallback:        TCPMux,
		EdgeID:          "edge-a",
		FailureDomains:  []string{"domain-a", "domain-b"},
		Session:         testDataCarrierIdentity(),
		Carrier:         config,
	}

	var (
		mu       sync.Mutex
		calls    []Transport
		requests []DataCarrierDialRequest
		servers  []*DataCarrier
	)
	dialer := func(ctx context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		mu.Lock()
		calls = append(calls, request.Transport)
		requests = append(requests, request)
		mu.Unlock()
		if request.Transport == QUIC {
			return DataCarrierDialResult{}, &TransportDialError{Transport: request.Transport, Err: errors.New("udp unavailable"), Fallback: true}
		}
		local, remote := net.Pipe()
		server, err := NewDataCarrierServer(context.Background(), remote, config, DataCarrierAdmission{Identity: testDataCarrierIdentity(), Authorize: func(context.Context, StreamOpen) error { return nil }})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return DataCarrierDialResult{}, err
		}
		mu.Lock()
		servers = append(servers, server)
		mu.Unlock()
		return DataCarrierDialResult{Link: local, PeerIdentity: request.Identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
	pool, err := NewDataCarrierPool(context.Background(), poolConfig, dialer)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()
	if err := pool.Connect(context.Background()); err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	if pool.State() != DataCarrierPoolReady {
		t.Fatalf("pool state = %s, want ready", pool.State())
	}
	select {
	case <-pool.Ready():
	default:
		t.Fatal("pool did not publish readiness after carrier ping")
	}
	selected, ok := pool.SelectedTransport()
	if !ok || selected != TCPMux {
		t.Fatalf("selected transport = %q, %v, want tcp mux", selected, ok)
	}
	if got := len(pool.Snapshot()); got != 2 {
		t.Fatalf("carrier count = %d, want 2", got)
	}
	mu.Lock()
	gotCalls := append([]Transport(nil), calls...)
	gotRequests := append([]DataCarrierDialRequest(nil), requests...)
	serverCarriers := append([]*DataCarrier(nil), servers...)
	mu.Unlock()
	if len(gotCalls) != 4 || gotCalls[0] != QUIC || gotCalls[1] != TCPMux || gotCalls[2] != QUIC || gotCalls[3] != TCPMux {
		t.Fatalf("dial sequence = %v, want QUIC/TCPMux twice", gotCalls)
	}
	if gotRequests[0].Slot != 0 || gotRequests[0].Attempt != 1 || gotRequests[0].FailureDomain != "domain-a" || gotRequests[1].Slot != 0 || gotRequests[1].Attempt != 2 || gotRequests[1].FailureDomain != "domain-a" || gotRequests[2].Slot != 1 || gotRequests[2].Attempt != 1 || gotRequests[2].FailureDomain != "domain-b" || gotRequests[3].Slot != 1 || gotRequests[3].Attempt != 2 || gotRequests[3].FailureDomain != "domain-b" {
		t.Fatalf("dial requests = %+v, want slot/domain/attempt binding", gotRequests)
	}
	for _, info := range pool.Snapshot() {
		if info.EdgeID != "edge-a" || (info.Slot == 0 && info.FailureDomain != "domain-a") || (info.Slot == 1 && info.FailureDomain != "domain-b") || info.Attempt != 2 {
			t.Fatalf("carrier info = %+v, want explicit identity", info)
		}
	}

	acceptContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan io.ReadWriteCloser, len(serverCarriers))
	for _, server := range serverCarriers {
		go func(server *DataCarrier) {
			stream, _, err := server.AcceptStream(acceptContext)
			if err == nil {
				accepted <- stream
			}
		}(server)
	}
	stream, err := pool.OpenStream(acceptContext, testDataCarrierStreamOpen("route-a", "request-pooled"))
	if err != nil {
		t.Fatalf("open pooled stream: %v", err)
	}
	serverStream := <-accepted
	if _, err := stream.Write([]byte("pooled")); err != nil {
		t.Fatalf("write pooled stream: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close pooled stream: %v", err)
	}
	_ = serverStream.Close()

	control, err := pool.OpenControlStream(context.Background())
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	if _, err := pool.OpenControlStream(context.Background()); !errors.Is(err, ErrDataCarrierControlOpen) {
		t.Fatalf("second control stream error = %v, want %v", err, ErrDataCarrierControlOpen)
	}
	_ = control.Close()
	if !waitForDataCarrier(func() bool { return pool.totalActive() == 0 }) {
		t.Fatalf("pool streams did not drain")
	}
	if err := pool.Drain(context.Background()); err != nil {
		t.Fatalf("drain pool: %v", err)
	}
	if pool.State() != DataCarrierPoolClosed {
		t.Fatalf("pool state after drain = %s, want closed", pool.State())
	}
}

func TestDataCarrierPoolRejectsAmbiguousFallback(t *testing.T) {
	config := DefaultDataCarrierPoolConfig()
	p, err := NewDataCarrierPool(context.Background(), config, func(context.Context, DataCarrierDialRequest) (DataCarrierDialResult, error) {
		return DataCarrierDialResult{}, context.DeadlineExceeded
	})
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer p.Close()
	if err := p.Connect(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connect error = %v, want deadline exceeded", err)
	}
}

func TestDataCarrierPoolTransportValidation(t *testing.T) {
	config := DefaultDataCarrierPoolConfig()
	config.Preferred = TCPMux
	config.Fallback = TCPMux
	if err := config.Validate(); !errors.Is(err, ErrInvalidDataCarrierConfig) {
		t.Fatalf("equal transport validation error = %v, want invalid config", err)
	}
	config.SingleTransport = true
	if err := config.Validate(); err != nil {
		t.Fatalf("single transport validation: %v", err)
	}
	config.SingleTransport = false
	config.Preferred = TCPDedicated
	config.Fallback = QUIC
	if err := config.Validate(); !errors.Is(err, ErrInvalidDataCarrierConfig) {
		t.Fatalf("unsupported transport validation error = %v, want invalid config", err)
	}
}

func TestDataCarrierPingAndOpenCloseDoNotLeak(t *testing.T) {
	config := testDataCarrierConfig()
	config.StreamOpenLimit = 100 * time.Millisecond
	config.ConnectionWriteLimit = 100 * time.Millisecond
	local, remote := net.Pipe()
	client, err := NewDataCarrierClient(context.Background(), local, config)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		t.Fatalf("new client: %v", err)
	}
	pingContext, cancelPing := context.WithTimeout(context.Background(), 20*time.Millisecond)
	pingDone := make(chan error, 1)
	go func() { pingDone <- client.Ping(pingContext) }()
	select {
	case err := <-pingDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ping error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled ping did not return")
	}
	cancelPing()
	openContext, cancelOpen := context.WithTimeout(context.Background(), 20*time.Millisecond)
	openDone := make(chan error, 1)
	go func() {
		_, openErr := client.OpenStream(openContext)
		openDone <- openErr
	}()
	select {
	case <-openDone:
	case <-time.After(time.Second):
		t.Fatal("canceled open did not return")
	}
	cancelOpen()
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	_ = remote.Close()
	if client.ActiveStreams() != 0 {
		t.Fatalf("active streams after close = %d", client.ActiveStreams())
	}
	if _, err := client.OpenStream(context.Background()); !errors.Is(err, ErrDataCarrierClosed) {
		t.Fatalf("open after close error = %v, want closed", err)
	}
}

func TestPreparedDataCarrierStagesReadinessAndExplicitActivation(t *testing.T) {
	identity := testDataCarrierIdentity()
	config := DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	config.Carrier = testDataCarrierConfig()
	var edgeCarriers []*DataCarrier
	dialer := func(_ context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		if request.Slot != 0 || request.Attempt != 1 || request.FailureDomain != "domain-a" {
			return DataCarrierDialResult{}, errors.New("unexpected dial request")
		}
		local, remote := net.Pipe()
		edge, err := NewDataCarrierServer(context.Background(), remote, config.Carrier, DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, StreamOpen) error { return nil }})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return DataCarrierDialResult{}, err
		}
		edgeCarriers = append(edgeCarriers, edge)
		return DataCarrierDialResult{Link: local, PeerIdentity: request.Identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
	prepared, err := PrepareDataCarrier(context.Background(), identity, config, dialer)
	if err != nil {
		t.Fatalf("prepare carrier: %v", err)
	}
	if prepared.State() != "prepared" {
		t.Fatalf("prepared state = %q", prepared.State())
	}
	select {
	case <-prepared.Ready():
	default:
		t.Fatal("prepared carrier is not ready after authenticated ping")
	}
	selected, ok := prepared.SelectedTransport()
	if !ok || selected != QUIC {
		t.Fatalf("selected transport = %q/%v, want quic/true", selected, ok)
	}
	snapshot := prepared.Snapshot()
	if len(snapshot) != 1 || snapshot[0].FailureDomain != "domain-a" || snapshot[0].Slot != 0 || snapshot[0].Attempt != 1 {
		t.Fatalf("carrier snapshot = %+v", snapshot)
	}
	active, err := prepared.Activate(context.Background())
	if err != nil {
		t.Fatalf("activate carrier: %v", err)
	}
	if prepared.State() != "active" || len(active.Snapshot()) != 1 {
		t.Fatalf("active state/snapshot = %q/%+v", prepared.State(), active.Snapshot())
	}
	if err := prepared.Abort(context.Background()); !errors.Is(err, ErrDataCarrierUnavailable) {
		t.Fatalf("abort after activation = %v, want unavailable", err)
	}
	if err := active.Close(context.Background()); err != nil {
		t.Fatalf("close active carrier: %v", err)
	}
	for _, edge := range edgeCarriers {
		_ = edge.Close()
	}
}

func TestPrepareDataCarrierRejectsIdentityMismatch(t *testing.T) {
	identity := testDataCarrierIdentity()
	config := DefaultDataCarrierPoolConfig()
	config.Session = DataCarrierIdentity{AccountID: "other", HostID: "host-a", TunnelID: "tunnel-a", ConnectorID: "connector-a", SessionID: "session-a", ProcessGeneration: 7, Generation: 11}
	_, err := PrepareDataCarrier(context.Background(), identity, config, func(context.Context, DataCarrierDialRequest) (DataCarrierDialResult, error) {
		return DataCarrierDialResult{}, errors.New("dialer must not run")
	})
	if !errors.Is(err, ErrInvalidDataCarrierConfig) {
		t.Fatalf("mismatched identity error = %v, want invalid config", err)
	}
}

func TestActiveDataCarrierBeginDrainFencesAdmissionAndPreservesExistingStream(t *testing.T) {
	identity := testDataCarrierIdentity()
	config := DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.SingleTransport = true
	config.Preferred = QUIC
	config.Fallback = QUIC
	config.EdgeID = "edge-a"
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	config.Carrier = testDataCarrierConfig()
	accepted := make(chan io.ReadWriteCloser, 1)
	var edge *DataCarrier
	dialer := func(_ context.Context, request DataCarrierDialRequest) (DataCarrierDialResult, error) {
		local, remote := net.Pipe()
		var err error
		edge, err = NewDataCarrierServer(context.Background(), remote, config.Carrier, DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, StreamOpen) error { return nil }})
		if err != nil {
			_ = local.Close()
			_ = remote.Close()
			return DataCarrierDialResult{}, err
		}
		go func() {
			stream, _, acceptErr := edge.AcceptStream(context.Background())
			if acceptErr == nil {
				accepted <- stream
			}
		}()
		return DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	}
	prepared, err := PrepareDataCarrier(context.Background(), identity, config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	active, err := prepared.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := active.OpenStream(context.Background(), testDataCarrierStreamOpen("route-a", "request-drain-active"))
	if err != nil {
		t.Fatal(err)
	}
	edgeStream := <-accepted
	if active.ActiveStreams() != 1 {
		t.Fatalf("active streams = %d, want 1", active.ActiveStreams())
	}
	if err := active.BeginDrain(); err != nil {
		t.Fatal(err)
	}
	if _, err := active.OpenStream(context.Background(), testDataCarrierStreamOpen("route-a", "request-drain-rejected")); !errors.Is(err, ErrDataCarrierDraining) {
		t.Fatalf("new stream error = %v, want draining", err)
	}
	if _, err := stream.Write([]byte("still-open")); err != nil {
		t.Fatalf("existing stream write after begin drain: %v", err)
	}
	_ = stream.Close()
	_ = edgeStream.Close()
	if !waitForDataCarrier(func() bool { return active.ActiveStreams() == 0 }) {
		t.Fatalf("active streams after close = %d", active.ActiveStreams())
	}
	if err := active.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = edge.Close()
}

func TestDataCarrierIdentityRequiresHostBinding(t *testing.T) {
	identity := testDataCarrierIdentity()
	identity.HostID = ""
	config := DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	if err := config.Validate(); !errors.Is(err, ErrInvalidDataCarrierConfig) {
		t.Fatalf("missing host identity validation error = %v, want invalid config", err)
	}
}

func dataCarrierPair(t *testing.T, config DataCarrierConfig) (*DataCarrier, *DataCarrier) {
	t.Helper()
	local, remote := net.Pipe()
	identity := testDataCarrierIdentity()
	serverAdmission := DataCarrierAdmission{Identity: identity, Authorize: func(context.Context, StreamOpen) error { return nil }}
	server, err := NewDataCarrierServer(context.Background(), remote, config, serverAdmission)
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		t.Fatalf("new server carrier: %v", err)
	}
	client, err := NewDataCarrierClient(context.Background(), local, config, identity)
	if err != nil {
		_ = server.Close()
		_ = local.Close()
		t.Fatalf("new client carrier: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func waitForDataCarrier(predicate func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return predicate()
}

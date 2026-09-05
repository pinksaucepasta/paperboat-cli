package tunnelmanager

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
)

type initialControlTestStream struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newInitialControlTestStream() *initialControlTestStream {
	return &initialControlTestStream{closed: make(chan struct{})}
}

func (s *initialControlTestStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *initialControlTestStream) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (s *initialControlTestStream) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func waitInitialControlStreamClosed(t *testing.T, stream *initialControlTestStream) {
	t.Helper()
	select {
	case <-stream.closed:
	case <-time.After(time.Second):
		t.Fatal("initial control stream was not closed")
	}
}

func TestProductionAssemblyInitialControlRetriesTransientAcquisitionFailure(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	transientErr := errors.New("control endpoint temporarily unavailable")
	reports := make(chan Observation, 1)
	config.Production.Report = func(observation Observation) {
		reports <- observation
	}
	secondStream := newInitialControlTestStream()
	var calls int
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		calls++
		if calls == 1 {
			return nil, transientErr
		}
		return secondStream, nil
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Shutdown(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := assembly.acquireInitialControl(ctx)
	if err != nil {
		t.Fatalf("initial control acquisition = %v", err)
	}
	if stream != secondStream {
		t.Fatal("initial control acquisition did not return the successful stream")
	}
	if calls != 2 {
		t.Fatalf("control stream calls = %d, want 2", calls)
	}
	select {
	case observation := <-reports:
		if observation.Code != CodeControlUnavailable || !observation.Retryable {
			t.Fatalf("transient acquisition observation = %+v", observation)
		}
		if !errors.Is(observation.Err, transientErr) {
			t.Fatalf("transient acquisition observation error = %v, want %v", observation.Err, transientErr)
		}
	case <-time.After(time.Second):
		t.Fatal("transient acquisition failure was not reported")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close successful stream: %v", err)
	}
}

func TestProductionAssemblyInitialControlCancellationStopsBackoff(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	reported := make(chan struct{})
	config.Production.Report = func(Observation) { close(reported) }
	var calls int
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		calls++
		return nil, errors.New("control endpoint unavailable")
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Shutdown(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	acquisitionDone := make(chan error, 1)
	go func() {
		_, acquisitionErr := assembly.acquireInitialControl(ctx)
		acquisitionDone <- acquisitionErr
	}()
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("initial control failure was not reported")
	}
	cancel()

	select {
	case err := <-acquisitionDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled acquisition error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial control acquisition did not stop during backoff")
	}
	if calls != 1 {
		t.Fatalf("control stream calls after cancellation = %d, want 1", calls)
	}
}

func TestProductionAssemblyInitialControlClosesReturnedStreamOnProviderError(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	providerErr := errors.New("control provider returned a failed stream")
	stream := newInitialControlTestStream()
	config.ControlStream = func(context.Context) (io.ReadWriteCloser, error) {
		return stream, providerErr
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Shutdown(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	acquisitionDone := make(chan error, 1)
	go func() {
		_, acquisitionErr := assembly.acquireInitialControl(ctx)
		acquisitionDone <- acquisitionErr
	}()
	waitInitialControlStreamClosed(t, stream)
	cancel()
	if err := <-acquisitionDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("provider-error acquisition error = %v, want context.Canceled after retry cancellation", err)
	}
}

func TestProductionAssemblyInitialControlClosesStreamWhenContextCancelsAfterProviderReturn(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	stream := newInitialControlTestStream()
	ctx, cancel := context.WithCancel(context.Background())
	config.ControlStream = func(context.Context) (io.ReadWriteCloser, error) {
		cancel()
		return stream, nil
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer assembly.Shutdown(context.Background())

	_, err = assembly.acquireInitialControl(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled successful-return acquisition error = %v, want context.Canceled", err)
	}
	waitInitialControlStreamClosed(t, stream)
}

func TestProductionAssemblyInitialControlDoesNotFabricateReadyOrPromotion(t *testing.T) {
	config := newProductionAssemblyConfig(t)
	identity := config.SessionSource.Identity
	liveSessionSource := config.SessionSource
	config.SessionSource = connector.DataCarrierSessionSource{}
	var descriptorMu sync.Mutex
	var descriptorCalls int
	config.CarrierDescriptorSource = func(context.Context, connectorprotocol.Welcome, ApplyRequest) (connector.DataCarrierSessionSource, error) {
		descriptorMu.Lock()
		defer descriptorMu.Unlock()
		descriptorCalls++
		return liveSessionSource, nil
	}
	server, client := net.Pipe()
	config.ControlStream = func(ctx context.Context) (io.ReadWriteCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return client, nil
	}
	config.ControlSessionFactory = func(context.Context, *CoordinatedConfigApplier) (connectorrotation.ControlSessionConfig, error) {
		return config.Control, nil
	}

	assembly, _, err := OpenProductionAssembly(config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer assembly.Shutdown(context.Background())

	snapshotValue, err := connectorprotocol.NewSnapshot(identity.TunnelID, 1, tunnelSnapshot(t, 1).Payload)
	if err != nil {
		t.Fatal(err)
	}
	snapshotValue.AccountID = identity.AccountID
	snapshotValue.ConnectorID = identity.ConnectorID
	snapshotValue.SessionID = "session-before-welcome"
	snapshotValue.ProcessGeneration = identity.ProcessGeneration
	if _, err := assembly.Applier.PrepareSnapshot(context.Background(), snapshotValue); err != nil {
		t.Fatalf("stage desired snapshot: %v", err)
	}
	if err := assembly.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorprotocol.ReadFrame(server); err != nil {
		t.Fatalf("read initial hello: %v", err)
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		descriptorMu.Lock()
		gotDescriptorCalls := descriptorCalls
		descriptorMu.Unlock()
		if gotDescriptorCalls != 0 {
			t.Fatalf("carrier descriptor was prepared before Welcome: %d calls", gotDescriptorCalls)
		}
		if got := assembly.ResourceCounts()["tunnels"]; got != 0 {
			t.Fatalf("active tunnel count before Welcome = %d, want 0", got)
		}
		if _, active := assembly.Control.Session().Active(); active {
			t.Fatal("control session fabricated an active snapshot before Welcome")
		}
		if state := assembly.Control.Session().State(); state != connectorprotocol.SessionNew {
			t.Fatalf("control session state before Welcome = %s, want %s", state, connectorprotocol.SessionNew)
		}
		time.Sleep(5 * time.Millisecond)
	}
	descriptorMu.Lock()
	gotDescriptorCalls := descriptorCalls
	descriptorMu.Unlock()
	if gotDescriptorCalls != 0 {
		t.Fatalf("carrier descriptor calls before Welcome = %d, want 0", gotDescriptorCalls)
	}
}

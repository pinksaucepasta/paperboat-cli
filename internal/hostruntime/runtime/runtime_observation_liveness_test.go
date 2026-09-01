//go:build darwin || linux || windows

package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type livenessObservationTokenSource struct{}

func (livenessObservationTokenSource) Token(context.Context) (string, error) {
	return "runtime-observation-token", nil
}

type livenessObservationProofSource struct{}

func (livenessObservationProofSource) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("runtime-observation-proof"), nil
}

type livenessObservationTransport struct {
	calls  atomic.Int64
	mu     sync.Mutex
	times  []time.Time
	notify chan struct{}
}

func (t *livenessObservationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/runtime-observations" {
		return nil, &urlPathError{method: request.Method, path: request.URL.Path}
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	_ = request.Body.Close()
	var payload struct {
		SampledAt time.Time `json:"sampled_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	t.calls.Add(1)
	t.mu.Lock()
	t.times = append(t.times, payload.SampledAt)
	t.mu.Unlock()
	select {
	case t.notify <- struct{}{}:
	default:
	}
	return &http.Response{
		StatusCode:    http.StatusAccepted,
		Header:        make(http.Header),
		Body:          io.NopCloser(nilReader{}),
		ContentLength: 0,
		Request:       request,
	}, nil
}

type urlPathError struct {
	method string
	path   string
}

func (e *urlPathError) Error() string {
	return "unexpected observation request " + e.method + " " + e.path
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestRuntimeObservationServiceContinuesAfterInitialAcceptance(t *testing.T) {
	transport := &livenessObservationTransport{notify: make(chan struct{}, 16)}
	sender := &runtimeObservationSender{
		endpoint:         "https://observations.invalid/v1/runtime-observations",
		tokens:           livenessObservationTokenSource{},
		proofs:           livenessObservationProofSource{},
		operationID:      func() (string, error) { return "op_runtime_observation_0001", nil },
		environmentID:    "env_runtime_observation",
		machineID:        "machine_runtime_observation",
		reporterVersion:  "test",
		client:           &http.Client{Transport: transport},
		receiptPath:      filepath.Join(t.TempDir(), "runtime", "server-heartbeat.json"),
		workerGeneration: 1,
		osBootID:         "boot-runtime-observation",
	}
	service := &runtimeObservationService{sender: sender, interval: 15 * time.Millisecond, timeout: 250 * time.Millisecond}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(shutdownCtx)
	}()

	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("initial observation calls = %d, want 1", got)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for transport.calls.Load() < 3 {
		select {
		case <-transport.notify:
		case <-deadline.C:
			t.Fatalf("periodic observation calls = %d, want at least 3", transport.calls.Load())
		}
	}

	transport.mu.Lock()
	times := append([]time.Time(nil), transport.times...)
	transport.mu.Unlock()
	if len(times) < 3 || !times[0].Before(times[1]) || !times[1].Before(times[2]) {
		t.Fatalf("observation timestamps = %v, want three increasing samples", times)
	}
	if _, err := readServerHeartbeatReceipt(sender.receiptPath); err != nil {
		t.Fatalf("heartbeat receipt after periodic observations: %v", err)
	}

	beforeShutdown := transport.calls.Load()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := service.Shutdown(shutdownCtx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if got := transport.calls.Load(); got < beforeShutdown+1 {
		t.Fatalf("shutdown calls = %d, want final observation after %d", got, beforeShutdown)
	}
	stoppedAt := transport.calls.Load()
	time.Sleep(4 * service.interval)
	if got := transport.calls.Load(); got != stoppedAt {
		t.Fatalf("observation loop continued after shutdown: calls=%d want=%d", got, stoppedAt)
	}
}

func TestRuntimeObservationServiceOutlivesStartupContext(t *testing.T) {
	transport := &livenessObservationTransport{notify: make(chan struct{}, 16)}
	sender := &runtimeObservationSender{
		endpoint:         "https://observations.invalid/v1/runtime-observations",
		tokens:           livenessObservationTokenSource{},
		proofs:           livenessObservationProofSource{},
		operationID:      func() (string, error) { return "op_runtime_observation_startup_0001", nil },
		environmentID:    "env_runtime_observation",
		machineID:        "machine_runtime_observation",
		reporterVersion:  "test",
		client:           &http.Client{Transport: transport},
		receiptPath:      filepath.Join(t.TempDir(), "runtime", "server-heartbeat.json"),
		workerGeneration: 1,
		osBootID:         "boot-runtime-observation",
	}
	service := &runtimeObservationService{sender: sender, interval: 15 * time.Millisecond, timeout: 250 * time.Millisecond}
	// Production host composition wraps the observation loop with the regional
	// monitor. Exercise the group itself so a caller-owned startup context
	// cannot accidentally become the lifetime of the second service.
	group := serviceGroup{runtimeObservationGroupMember{}, service}
	startupCtx, cancelStartup := context.WithCancel(context.Background())
	if err := group.Start(startupCtx); err != nil {
		t.Fatal(err)
	}
	cancelStartup()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for transport.calls.Load() < 2 {
		select {
		case <-transport.notify:
		case <-deadline.C:
			t.Fatalf("periodic observation stopped with startup context: calls=%d", transport.calls.Load())
		}
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := group.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

type runtimeObservationGroupMember struct{}

func (runtimeObservationGroupMember) Start(context.Context) error    { return nil }
func (runtimeObservationGroupMember) Shutdown(context.Context) error { return nil }

func readServerHeartbeatReceipt(path string) (serverHeartbeatReceipt, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return serverHeartbeatReceipt{}, err
	}
	var receipt serverHeartbeatReceipt
	err = json.Unmarshal(body, &receipt)
	return receipt, err
}

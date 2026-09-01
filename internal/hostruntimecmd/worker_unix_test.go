//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func TestRuntimeWorkerEntryActivatesFencedHostdLease(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "pbwrk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	token := bytes.Repeat([]byte{0x41}, 32)
	tokenPath := filepath.Join(root, "worker.token")
	if err := os.WriteFile(tokenPath, token, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := hostdproto.NewServer(hostdproto.SocketConfig{
		SocketPath: filepath.Join(root, "socket", "hostd.sock"), StatePath: filepath.Join(root, "state", "fence.json"),
		UID: os.Geteuid(), GID: os.Getegid(), Token: token, APIMin: 1, APIMax: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	t.Cleanup(func() { stopServer(); <-serverDone })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "socket", "hostd.sock")); err == nil {
			break
		}
		select {
		case err := <-serverDone:
			t.Fatalf("hostd socket failed to start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("hostd socket did not start")
		}
		time.Sleep(time.Millisecond)
	}

	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	done := make(chan error, 1)
	output := newLockedBuffer()
	go func() {
		done <- runWorker(workerCtx, []string{
			"--socket", filepath.Join(root, "socket", "hostd.sock"), "--token-file", tokenPath,
			"--worker-id", "runtime-test", "--version", "test", "--heartbeat", "1s",
		}, bytes.NewReader(nil), output, &bytes.Buffer{})
	}()
	const expectedOutput = "ready 1 1\nactive 1 1\n"
	activationCtx, cancelActivation := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelActivation()
	for output.String() != expectedOutput {
		select {
		case err := <-done:
			t.Fatalf("worker exited before activation: status=%+v output=%q err=%v", server.Status(), output.String(), err)
		case <-output.changed:
		case <-activationCtx.Done():
			t.Fatalf("worker did not activate before deadline: status=%+v output=%q", server.Status(), output.String())
		}
	}
	if status := server.Status(); status.State != hostdproto.StateActive {
		t.Fatalf("worker reported activation without active fence: status=%+v output=%q", status, output.String())
	}
	stopWorker()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if output.String() != expectedOutput {
		t.Fatalf("output=%q", output.String())
	}
}

// TestRunHostdKeepsStableObservationAliveAfterWorkerActivation protects the
// real hostd ownership boundary. The external worker is only a lifecycle
// candidate; activating or stopping it must not stop the stable host's
// presence loop. The production host factory is injected here only to keep
// the test deterministic and avoid starting a real control-plane client.
func TestRunHostdKeepsStableObservationAliveAfterWorkerActivation(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "pbh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	hostdRoot := filepath.Join(root, "hostd")
	if err := os.Mkdir(hostdRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hostdRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(hostdRoot, "hostd.sock")
	tokenPath := filepath.Join(root, "worker.token")
	token := bytes.Repeat([]byte{0x53}, 32)
	if err := os.WriteFile(tokenPath, token, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAPERBOAT_HOSTD_SOCKET", socket)
	t.Setenv("PAPERBOAT_HOSTD_TOKEN_FILE", tokenPath)
	t.Setenv("PAPERBOAT_RUNTIME_CURRENT", filepath.Join(root, "pb"))

	host := newRunHostdObservationHost()
	worker := &runHostdObservationWorker{host: host}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runHostdWith(ctx, io.Discard,
			func(context.Context, string, func(string) string) (hostdHost, error) {
				return host, nil
			},
			func(context.Context, workerupdate.StartRequest) (workerupdate.Worker, error) {
				return worker, nil
			},
		)
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for host.postActivation.Load() < 2 {
		select {
		case <-host.notify:
		case err := <-done:
			t.Fatalf("runHostd exited before worker activation: %v", err)
		case <-deadline.C:
			t.Fatalf("post-activation observations=%d, want at least 2; total=%d", host.postActivation.Load(), host.calls.Load())
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runHostd did not shut down")
	}
	if !worker.stopped.Load() {
		t.Fatal("hostd did not stop the external worker")
	}
	if !host.stopped.Load() {
		t.Fatal("hostd did not shut down the stable host")
	}
}

type runHostdObservationHost struct {
	calls          atomic.Int64
	postActivation atomic.Int64
	activated      atomic.Bool
	started        atomic.Bool
	stopped        atomic.Bool
	notify         chan struct{}
	stop           chan struct{}
	stopOnce       sync.Once
	done           chan struct{}
}

func newRunHostdObservationHost() *runHostdObservationHost {
	return &runHostdObservationHost{notify: make(chan struct{}, 16), stop: make(chan struct{}), done: make(chan struct{})}
}

func (h *runHostdObservationHost) StartHostd(context.Context) error {
	if !h.started.CompareAndSwap(false, true) {
		return nil
	}
	h.observe()
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		defer close(h.done)
		for {
			select {
			case <-ticker.C:
				h.observe()
			case <-h.stop:
				return
			}
		}
	}()
	return nil
}

func (h *runHostdObservationHost) ShutdownHostd(context.Context) error {
	h.stopOnce.Do(func() { close(h.stop) })
	if h.started.Load() {
		<-h.done
	}
	h.stopped.Store(true)
	return nil
}

func (h *runHostdObservationHost) WorkloadStatus() hostdproto.WorkloadStatus {
	return hostdproto.WorkloadStatus{Generation: 1}
}

func (*runHostdObservationHost) UpdateGate() hostdproto.UpdateGateHandler { return nil }

func (h *runHostdObservationHost) activate() {
	h.activated.Store(true)
}

func (h *runHostdObservationHost) observe() {
	h.calls.Add(1)
	if h.activated.Load() {
		h.postActivation.Add(1)
	}
	select {
	case h.notify <- struct{}{}:
	default:
	}
}

type runHostdObservationWorker struct {
	host    *runHostdObservationHost
	stopped atomic.Bool
}

func (w *runHostdObservationWorker) Ready(context.Context) (hostdproto.Status, error) {
	return hostdproto.Status{State: hostdproto.StateCandidate, WorkerID: "runtime-test", APIVersion: 1, Epoch: 1}, nil
}

func (w *runHostdObservationWorker) Activate(context.Context) (hostdproto.Status, error) {
	w.host.activate()
	return hostdproto.Status{State: hostdproto.StateActive, WorkerID: "runtime-test", APIVersion: 1, Epoch: 1}, nil
}

func (w *runHostdObservationWorker) Stop(context.Context) error {
	w.stopped.Store(true)
	return nil
}

type lockedBuffer struct {
	mu      sync.Mutex
	b       bytes.Buffer
	changed chan struct{}
}

func newLockedBuffer() *lockedBuffer {
	return &lockedBuffer{changed: make(chan struct{}, 1)}
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.b.Write(p)
	b.mu.Unlock()
	if n > 0 {
		select {
		case b.changed <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

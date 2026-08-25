//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
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
	if err := waitForHostdSocket(context.Background(), filepath.Join(root, "socket", "hostd.sock"), token, serverDone); err != nil {
		t.Fatalf("hostd socket failed to start: %v", err)
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

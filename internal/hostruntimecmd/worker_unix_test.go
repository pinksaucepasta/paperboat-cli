//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	deadline := time.Now().Add(time.Second)
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
	done := make(chan error, 1)
	var output bytes.Buffer
	go func() {
		done <- runWorker(workerCtx, []string{
			"--socket", filepath.Join(root, "socket", "hostd.sock"), "--token-file", tokenPath,
			"--worker-id", "runtime-test", "--version", "test", "--heartbeat", "1s",
		}, bytes.NewReader(nil), &output, &bytes.Buffer{})
	}()
	deadline = time.Now().Add(time.Second)
	for server.Status().State != hostdproto.StateActive || output.String() != "ready 1 1\nactive 1 1\n" {
		if time.Now().After(deadline) {
			t.Fatalf("worker did not activate: status=%+v output=%q", server.Status(), output.String())
		}
		time.Sleep(time.Millisecond)
	}
	stopWorker()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if output.String() != "ready 1 1\nactive 1 1\n" {
		t.Fatalf("output=%q", output.String())
	}
}

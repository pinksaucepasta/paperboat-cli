//go:build unix

package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

func commandLocalAPIServerConfig(path string, source localapi.SnapshotSource) (localapi.ServerConfig, error) {
	return localapi.ServerConfig{SocketPath: path, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), Source: source}, nil
}

func commandRuntimeTestRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "pb-command-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func waitForCommandSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", path, 20*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("local command socket %s was not ready", path)
}

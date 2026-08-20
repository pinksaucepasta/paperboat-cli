//go:build windows

package main

import (
	"context"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
	"testing"
	"time"
)

func commandLocalAPIServerConfig(path string, source localapi.SnapshotSource) (localapi.ServerConfig, error) {
	sid, err := localdaemon.CurrentUserSID()
	if err != nil {
		return localapi.ServerConfig{}, err
	}
	return localapi.ServerConfig{SocketPath: path, OwnerUID: -1, OwnerGID: -1, OwnerSID: sid, Source: source}, nil
}

func commandRuntimeTestRoot(t *testing.T) string { t.Helper(); return t.TempDir() }

func waitForCommandSocket(t *testing.T, path string) {
	t.Helper()
	client, err := localapi.NewClient(path, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err = client.Snapshot(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("local command pipe %s was not ready: %v", path, err)
}

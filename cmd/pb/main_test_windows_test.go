//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/localdaemon"
)

func commandLocalAPIServerConfig(path string, source localapi.SnapshotSource) (localapi.ServerConfig, error) {
	sid, err := localdaemon.CurrentUserSID()
	if err != nil {
		return localapi.ServerConfig{}, err
	}
	return localapi.ServerConfig{SocketPath: path, OwnerUID: -1, OwnerGID: -1, OwnerSID: sid, Source: source}, nil
}

func commandRuntimeTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("APPDATA", root)
	previous := []string{xdg.Home, xdg.ConfigHome, xdg.CacheHome, xdg.DataHome, xdg.StateHome, xdg.RuntimeDir}
	xdg.Home = root
	xdg.ConfigHome = root
	xdg.CacheHome = root
	xdg.DataHome = root
	xdg.StateHome = root
	xdg.RuntimeDir = root
	t.Cleanup(func() {
		xdg.Home, xdg.ConfigHome, xdg.CacheHome, xdg.DataHome, xdg.StateHome, xdg.RuntimeDir = previous[0], previous[1], previous[2], previous[3], previous[4], previous[5]
	})
	return root
}

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

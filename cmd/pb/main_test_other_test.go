//go:build !unix && !windows

package main

import (
	"testing"

	"github.com/adrg/xdg"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

func commandLocalAPIServerConfig(path string, source localapi.SnapshotSource) (localapi.ServerConfig, error) {
	return localapi.ServerConfig{SocketPath: path, OwnerUID: 0, OwnerGID: 0, Source: source}, nil
}

func commandRuntimeTestRoot(t *testing.T) string { t.Helper(); return t.TempDir() }

func isolateCommandCredentialLocation(t *testing.T, root string) {
	t.Helper()
	previous := xdg.ConfigHome
	xdg.ConfigHome = root
	t.Cleanup(func() { xdg.ConfigHome = previous })
}

func waitForCommandSocket(t *testing.T, _ string) { t.Helper() }

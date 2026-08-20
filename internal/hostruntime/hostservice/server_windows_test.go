//go:build windows

package hostservice

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type windowsTestApplier struct{}

func (windowsTestApplier) Apply(context.Context, string) error { return nil }
func (windowsTestApplier) Close(context.Context) error         { return nil }

func TestWindowsDiagnosticsRequestDoesNotRequireClientEOF(t *testing.T) {
	server, err := New(Config{
		SocketPath: `\\.\pipe\PaperboatHostServiceTest`,
		StatePath:  filepath.Join(t.TempDir(), "availability.json"),
		Applier:    windowsTestApplier{},
		Version:    "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- server.serve(peer)
		_ = peer.Close()
	}()
	if err := json.NewEncoder(client).Encode(Request{Schema: ProtocolV1, Operation: "diagnostics"}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("read response while write side remains open: %v", err)
	}
	if response.Schema != ProtocolV1 || response.HostServiceVersion != "test" || response.Scope != "system" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

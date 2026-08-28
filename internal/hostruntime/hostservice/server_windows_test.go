//go:build windows

package hostservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type windowsTestApplier struct{}

func (windowsTestApplier) Apply(context.Context, string) error { return nil }
func (windowsTestApplier) Close(context.Context) error         { return nil }

type windowsTestAuthorizedKeys struct {
	keys    []string
	changed bool
	err     error
}

func (r *windowsTestAuthorizedKeys) ReconcileAuthorizedKeys(_ context.Context, keys []string) (bool, error) {
	r.keys = make([]string, len(keys))
	copy(r.keys, keys)
	return r.changed, r.err
}

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

func TestWindowsAuthorizedKeysRequestUsesSIDRestrictedHostService(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current SID: %v", err)
	}
	pipe := `\\.\pipe\PaperboatHostServiceKeysTest-` + strconv.FormatInt(time.Now().UnixNano(), 10)
	ready := make(chan struct{})
	reconciler := &windowsTestAuthorizedKeys{changed: true}
	server, err := New(Config{
		SocketPath:     pipe,
		StatePath:      filepath.Join(t.TempDir(), "availability.json"),
		SID:            user.User.Sid.String(),
		Applier:        windowsTestApplier{},
		Version:        "test",
		AuthorizedKeys: reconciler,
		Ready: func() error {
			close(ready)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("host service did not become ready")
	}
	client, err := NewClient(pipe, 5*time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	keys := make([]string, 256)
	for index := range keys {
		keys[index] = "ssh-ed25519 " + strings.Repeat("a", 100) + strconv.Itoa(index)
	}
	changed, err := client.ReconcileAuthorizedKeys(context.Background(), keys)
	if err != nil || !changed || !reflect.DeepEqual(reconciler.keys, keys) {
		cancel()
		t.Fatalf("changed=%t keys=%d err=%v", changed, len(reconciler.keys), err)
	}
	reconciler.changed = false
	changed, err = client.ReconcileAuthorizedKeys(context.Background(), nil)
	if err != nil || changed || reconciler.keys == nil || len(reconciler.keys) != 0 {
		cancel()
		t.Fatalf("clear changed=%t keys=%v err=%v", changed, reconciler.keys, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("host service shutdown error: %v", err)
	}
}

func TestWindowsAuthorizedKeysClientRejectsMoreThanProtocolMaximum(t *testing.T) {
	client, err := NewClient(`\\.\pipe\PaperboatHostServiceDoesNotExist`, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReconcileAuthorizedKeys(context.Background(), make([]string, 257)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v, want invalid request", err)
	}
}

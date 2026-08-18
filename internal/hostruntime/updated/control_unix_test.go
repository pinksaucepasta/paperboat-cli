//go:build darwin || linux

package updated

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestControlClientUsesOnlyFixedOperations(t *testing.T) {
	path := testSocketPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := controlServer{socketPath: path, uid: os.Geteuid(), gid: os.Getegid(), invoke: func(_ context.Context, operation string) (ControlResponse, error) {
		if operation != "update" {
			t.Fatalf("operation = %q", operation)
		}
		return ControlResponse{Schema: ControlProtocolV1, Status: "ok", Version: "2.0.0", Updated: true}, nil
	}}
	done := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			_ = server.handle(connection)
			_ = connection.Close()
		}
		close(done)
	}()
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response.Version != "2.0.0" || !response.Updated {
		t.Fatalf("response = %#v", response)
	}
	<-done
}

func TestControlRejectsUnknownFields(t *testing.T) {
	path := testSocketPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := controlServer{socketPath: path, uid: os.Geteuid(), gid: os.Getegid(), invoke: func(context.Context, string) (ControlResponse, error) {
		t.Fatal("invoke must not run")
		return ControlResponse{}, nil
	}}
	done := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			_ = server.handle(connection)
			_ = connection.Close()
		}
		close(done)
	}()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte(`{"schema":"paperboat.updated/v1","operation":"status","unexpected":true}\n`)); err != nil {
		t.Fatal(err)
	}
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	_ = connection.Close()
	<-done
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	file, err := os.CreateTemp("", "pbupd-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path
}

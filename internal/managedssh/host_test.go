package managedssh

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestHostReconcilesAndServesGenerationFencedTarget(t *testing.T) {
	listener := loopbackListener(t)
	defer listener.Close()
	go echoConnections(listener)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	host, err := NewHost(HostConfig{MaxStreams: 2, ProbeTimeout: time.Second, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	target, err := host.ReconcileTarget(context.Background(), 3, port)
	if err != nil || target.Generation != 3 || target.Port != port || target.Readiness.Target.Port != port {
		t.Fatalf("target=%+v error=%v", target, err)
	}
	if replay, err := host.ReconcileTarget(context.Background(), 3, port); err != nil || replay != target {
		t.Fatalf("replay=%+v error=%v", replay, err)
	}
	if _, err := host.ReconcileTarget(context.Background(), 2, port); !errors.Is(err, ErrSSHHostStale) {
		t.Fatalf("stale reconcile error=%v", err)
	}
	client, server := net.Pipe()
	result := make(chan error, 1)
	go func() {
		_, err := host.Serve(context.Background(), 3, server)
		result <- err
	}()
	message := []byte("SSH-2.0-paperboat-test\r\n")
	if _, err := client.Write(message); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(client, got); err != nil || string(got) != string(message) {
		t.Fatalf("echo=%q error=%v", got, err)
	}
	_ = client.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := host.Serve(context.Background(), 4, pipeStream(t)); !errors.Is(err, ErrSSHHostStale) {
		t.Fatalf("stale serve error=%v", err)
	}
}

func TestHostEnforcesCapacity(t *testing.T) {
	listener := loopbackListener(t)
	defer listener.Close()
	go echoConnections(listener)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	host, _ := NewHost(HostConfig{MaxStreams: 1, ProbeTimeout: time.Second, DialTimeout: time.Second})
	if _, err := host.ReconcileTarget(context.Background(), 1, port); err != nil {
		t.Fatal(err)
	}
	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	firstDone := make(chan error, 1)
	go func() { _, err := host.Serve(context.Background(), 1, firstServer); firstDone <- err }()
	deadline := time.Now().Add(time.Second)
	for len(host.capacity) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	secondClient, secondServer := net.Pipe()
	defer secondClient.Close()
	defer secondServer.Close()
	if _, err := host.Serve(context.Background(), 1, secondServer); !errors.Is(err, ErrSSHHostBusy) {
		t.Fatalf("capacity error=%v", err)
	}
	_ = firstClient.Close()
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func echoConnections(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(connection, connection)
			_ = connection.Close()
		}()
	}
}

func pipeStream(t *testing.T) io.ReadWriteCloser {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left
}

package preview

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
)

func TestStartPrivateTCPProxyUsesAuthorizedCarrierAndLiteralLoopback(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetPort := uint16(target.Addr().(*net.TCPAddr).Port)
	targetDone := make(chan error, 1)
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr == nil {
			_, readErr = io.WriteString(connection, "echo:"+line)
		}
		targetDone <- readErr
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opens atomic.Int32
	proxy, err := StartPrivateTCPProxy(ctx, PrivateTCPProxyConfig{
		TargetPort: targetPort, MaximumConnections: 2,
		OpenStream: func(openContext context.Context) (io.ReadWriteCloser, error) {
			opens.Add(1)
			client, edge := net.Pipe()
			go func() {
				_ = peerpreview.Serve(openContext, edge, (&net.Dialer{}).DialContext)
			}()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if opens.Load() != 1 {
		t.Fatalf("authorized carrier opens after preflight = %d, want 1", opens.Load())
	}
	address := strings.TrimPrefix(proxy.URL, "http://")
	if !strings.HasPrefix(address, "127.0.0.1:") {
		t.Fatalf("proxy address=%q, want literal IPv4 loopback", address)
	}
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "private-canary\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	_ = connection.Close()
	if err != nil || line != "echo:private-canary\n" {
		t.Fatalf("private TCP response=%q error=%v", line, err)
	}
	select {
	case err := <-targetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("literal loopback target did not receive stream")
	}
}

func TestStartPrivateTCPProxyBoundsLifecycleAndRejectsInvalidTarget(t *testing.T) {
	if _, err := StartPrivateTCPProxy(context.Background(), PrivateTCPProxyConfig{OpenStream: func(context.Context) (io.ReadWriteCloser, error) { return nil, nil }}); !errors.Is(err, ErrPrivateTCPClientInvalid) {
		t.Fatalf("invalid target error=%v, want %v", err, ErrPrivateTCPClientInvalid)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var remoteClosed chan struct{}
	proxy, err := StartPrivateTCPProxy(ctx, PrivateTCPProxyConfig{
		TargetPort: 8080, MaximumConnections: 1,
		OpenStream: func(openContext context.Context) (io.ReadWriteCloser, error) {
			client, edge := net.Pipe()
			remoteClosed = make(chan struct{})
			go func() {
				defer close(remoteClosed)
				_ = peerpreview.Serve(openContext, edge, func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("target unavailable")
				})
			}()
			return client, nil
		},
	})
	if err == nil {
		_ = proxy.Close()
		t.Fatal("unavailable target unexpectedly started")
	}
	if !errors.Is(err, ErrPrivateTCPClientUnavailable) {
		t.Fatalf("unavailable target error=%v", err)
	}
	if remoteClosed == nil {
		t.Fatal("carrier source was not called for preflight")
	}
	select {
	case <-remoteClosed:
	case <-time.After(time.Second):
		t.Fatal("failed preflight did not close authorized stream")
	}
	cancel()
}

func TestStartPrivateTCPProxyRejectsNilContext(t *testing.T) {
	var nilContext context.Context
	if _, err := StartPrivateTCPProxy(nilContext, PrivateTCPProxyConfig{TargetPort: 1, OpenStream: func(context.Context) (io.ReadWriteCloser, error) { return nil, nil }}); !errors.Is(err, ErrPrivateTCPClientInvalid) {
		t.Fatalf("nil context error=%v", err)
	}
}

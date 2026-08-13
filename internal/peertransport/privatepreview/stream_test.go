package privatepreview

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestStreamProxiesBytesOnlyToIPv4Loopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr == nil && line == "request\n" {
			_, readErr = io.WriteString(connection, "response\n")
		}
		targetDone <- readErr
	}()
	client, host := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	served := make(chan error, 1)
	wantPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	go func() {
		served <- Serve(ctx, host, func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp4" || address != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(wantPort))) {
				return nil, ErrInvalid
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		})
	}()
	if err := Open(ctx, client, wantPort); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "request\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || line != "response\n" {
		t.Fatalf("response=%q err=%v", line, err)
	}
	_ = client.Close()
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestStreamDeliversCompleteResponseAfterTargetEOF(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	want := bytes.Repeat([]byte("preview-response-"), 64<<10)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = connection.Write(want)
		_ = connection.Close()
	}()
	client, host := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	served := make(chan error, 1)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	go func() {
		served <- Serve(ctx, host, (&net.Dialer{}).DialContext)
	}()
	if err := Open(ctx, client, port); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("response bytes changed")
	}
	_ = client.Close()
	select {
	case <-served:
	case <-ctx.Done():
		t.Fatal("preview bridge did not finish")
	}
}

func TestStreamReportsTargetUnavailable(t *testing.T) {
	client, host := net.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- Serve(context.Background(), host, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("refused")
		})
	}()
	if err := Open(context.Background(), client, 8080); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("open err=%v", err)
	}
	if err := <-served; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("serve err=%v", err)
	}
}

func TestOpenCancellationClosesBlockedStream(t *testing.T) {
	client, host := net.Pipe()
	defer host.Close()
	ctx, cancel := context.WithCancel(context.Background())
	opened := make(chan error, 1)
	go func() { opened <- Open(ctx, client, 8080) }()
	request := make([]byte, requestSize)
	if _, err := io.ReadFull(host, request); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-opened:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("open err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled open remained blocked")
	}
	var value [1]byte
	if _, err := host.Read(value[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("host read err=%v", err)
	}
}

func TestStreamRejectsMalformedPrefaceWithoutDialing(t *testing.T) {
	client, host := net.Pipe()
	dialed := false
	served := make(chan error, 1)
	go func() {
		served <- Serve(context.Background(), host, func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, nil
		})
	}()
	_, _ = client.Write([]byte("invalid"))
	if err := <-served; !errors.Is(err, ErrInvalid) {
		t.Fatalf("serve err=%v", err)
	}
	if dialed {
		t.Fatal("malformed preface reached dialer")
	}
}

package wsscarrier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestBinaryCarrierPartialReadsAndRemoteIdentity(t *testing.T) {
	client, server, closePair := carrierPair(t)
	defer closePair()
	payload := bytes.Repeat([]byte("private"), 128)
	writeDone := make(chan error, 1)
	go func() { _, err := client.Write(payload); writeDone <- err }()
	got := make([]byte, len(payload))
	for offset := 0; offset < len(got); {
		n, err := server.Read(got[offset : offset+min(17, len(got)-offset)])
		if err != nil {
			t.Fatal(err)
		}
		offset += n
	}
	if err := <-writeDone; err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("write=%v payload=%v", err, bytes.Equal(got, payload))
	}
	if got := server.RemoteAddr().String(); got != "paperboat-relay/edge_01" {
		t.Fatalf("remote=%q", got)
	}
}

func TestCarrierSerializesConcurrentWrites(t *testing.T) {
	client, server, closePair := carrierPair(t)
	defer closePair()
	const count = 16
	read := make(chan string, count)
	go func() {
		for range count {
			value := make([]byte, 2)
			if _, err := io.ReadFull(server, value); err != nil {
				return
			}
			read <- string(value)
		}
	}()
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) { defer wait.Done(); _, _ = client.Write([]byte{byte(index), byte(index)}) }(index)
	}
	wait.Wait()
	for range count {
		value := <-read
		if len(value) != 2 || value[0] != value[1] {
			t.Fatalf("interleaved=%v", []byte(value))
		}
	}
}

func TestCarrierRejectsLimitsAndUnsafeIdentity(t *testing.T) {
	if _, err := New(context.Background(), nil, Config{}); err == nil {
		t.Fatal("nil connection accepted")
	}
	client, _, closePair := carrierPair(t)
	defer closePair()
	if n, err := client.Write(make([]byte, MaximumMessageBytes+1)); err == nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if err := client.SetDeadline(time.Now().Add(time.Hour)); err == nil {
		t.Fatal("unbounded deadline accepted")
	}
}

func TestCarrierReadDeadlineClosesConnection(t *testing.T) {
	client, _, closePair := carrierPair(t)
	defer closePair()
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read=%v", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second read=%v", err)
	}
}

func TestCarrierParentCancellationStopsRead(t *testing.T) {
	clientWS, serverWS, server := websocketPair(t)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	client, err := New(ctx, clientWS, Config{RelayID: "edge_01", MaximumDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("read=%v", err)
	}
	_ = serverWS.CloseNow()
}

func TestCarrierWrongMessageTypeAndNormalClose(t *testing.T) {
	var accepted *websocket.Conn
	ready := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		accepted = connection
		close(ready)
		<-request.Context().Done()
	}))
	defer server.Close()
	clientWS, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		t.Fatal(err)
	}
	<-ready
	client, err := New(context.Background(), clientWS, Config{RelayID: "edge_01", MaximumDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted.Write(context.Background(), websocket.MessageText, []byte("private")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 32)); err == nil {
		t.Fatal("text frame accepted")
	}
	_ = client.Close()

	normalClient, normalServer, closeNormal := carrierPair(t)
	defer closeNormal()
	closed := make(chan error, 1)
	go func() { closed <- normalServer.Close() }()
	if _, err := normalClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("normal read=%v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("normal close=%v", err)
	}
}

func carrierPair(t *testing.T) (*Conn, *Conn, func()) {
	t.Helper()
	clientWS, serverWS, server := websocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	client, err := New(ctx, clientWS, Config{RelayID: "edge_01", MaximumDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := New(ctx, serverWS, Config{RelayID: "edge_01", MaximumDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return client, peer, func() {
		cancel()
		var wait sync.WaitGroup
		wait.Add(2)
		go func() { defer wait.Done(); _ = client.Close() }()
		go func() { defer wait.Done(); _ = peer.Close() }()
		wait.Wait()
		server.Close()
	}
}

func websocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, *httptest.Server) {
	t.Helper()
	serverConn := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err == nil {
			serverConn <- connection
		}
	}))
	clientWS, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	serverWS := <-serverConn
	return clientWS, serverWS, server
}

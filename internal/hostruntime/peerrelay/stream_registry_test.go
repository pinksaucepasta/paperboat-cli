package peerrelay

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/resumablestream"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/streamauth"
)

func registryHeader(t *testing.T, operation string) streamauth.Header {
	t.Helper()
	header, err := streamauth.New(operation, "ssh", "0123456789abcdef0123456789abcdef", "credential", time.Now().Add(time.Hour), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	header.Resumable = true
	return header
}

func registryClient(t *testing.T, principal string, header streamauth.Header) *resumablestream.Conn {
	t.Helper()
	client, err := resumablestream.New(t.Context(), resumablestream.Config{WindowBytes: resumableWindow, Role: resumablestream.RoleInitiator, Identity: resumablestream.StreamIdentity{Principal: principal, OperationID: header.OperationID, Consumer: header.Consumer, StreamID: header.StreamID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func registryCarrier(t *testing.T, registry *streamRegistry, client *resumablestream.Conn, principal string, header streamauth.Header, handler StreamHandler, initial bool) (net.Conn, resumablestream.CarrierHandle) {
	t.Helper()
	local, remote := net.Pipe()
	accepted := make(chan error, 1)
	go func() { accepted <- registry.Attach(principal, header, remote, handler) }()
	if initial {
		if err := client.AttachInitial(t.Context(), local); err != nil {
			t.Fatal(err)
		}
	} else {
		handle, err := client.PrepareCarrier(t.Context(), local)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-accepted; err != nil {
			t.Fatal(err)
		}
		return local, handle
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	return local, resumablestream.CarrierHandle{}
}

func TestStreamRegistryPromotesCarrierWithoutReinvokingHandler(t *testing.T) {
	registry := newStreamRegistry()
	defer registry.Close()
	header := registryHeader(t, "op_reattach")
	called := make(chan struct{}, 2)
	handler := func(_ context.Context, _ streamauth.Header, conn net.Conn) error {
		called <- struct{}{}
		for range 2 {
			value := make([]byte, 4)
			if _, err := io.ReadFull(conn, value); err != nil {
				return err
			}
			if _, err := conn.Write(value); err != nil {
				return err
			}
		}
		return nil
	}
	client := registryClient(t, "peer", header)
	primary, _ := registryCarrier(t, registry, client, "peer", header, handler, true)
	exchange := func(value []byte) {
		if _, err := client.Write(value); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(value))
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, value) {
			t.Fatalf("got=%q err=%v", got, err)
		}
	}
	exchange([]byte("one1"))
	_, handle := registryCarrier(t, registry, client, "peer", header, handler, false)
	if err := client.PromoteCarrier(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	_ = primary.Close()
	exchange([]byte("two2"))
	if len(called) != 1 {
		t.Fatalf("handler calls=%d", len(called))
	}
}

func TestStreamRegistryPrincipalMismatchRejectsCarrier(t *testing.T) {
	registry := newStreamRegistry()
	defer registry.Close()
	header := registryHeader(t, "op_identity")
	client := registryClient(t, "peer_a", header)
	local, remote := net.Pipe()
	accepted := make(chan error, 1)
	go func() {
		accepted <- registry.Attach("peer_b", header, remote, func(context.Context, streamauth.Header, net.Conn) error { return nil })
	}()
	if err := client.AttachInitial(t.Context(), local); err == nil {
		t.Fatal("principal mismatch accepted")
	}
	if err := <-accepted; err == nil {
		t.Fatal("registry accepted mismatched identity")
	}
}

func TestStreamRegistryHandlerReturnDeliversEOF(t *testing.T) {
	registry := newStreamRegistry()
	defer registry.Close()
	header := registryHeader(t, "op_eof")
	client := registryClient(t, "peer", header)
	registryCarrier(t, registry, client, "peer", header, func(_ context.Context, _ streamauth.Header, conn net.Conn) error {
		_, err := conn.Write([]byte("complete"))
		return err
	}, true)
	payload := make([]byte, len("complete"))
	if _, err := io.ReadFull(client, payload); err != nil || string(payload) != "complete" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("EOF=%v", err)
	}
}

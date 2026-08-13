package relaycarrier

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaynoise"
)

func TestSecureConnCarriesStreamBytesAcrossNoiseRecords(t *testing.T) {
	client, server, _ := wssPair(t, 4)
	initiator, responder, handle, prologue := testIdentities(t, relaynoise.CarrierWSS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type accepted struct {
		stream *SecureStream
		err    error
	}
	result := make(chan accepted, 1)
	go func() {
		stream, _, err := server.Accept(ctx, ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle, Authorize: func(context.Context, []byte) ([]byte, error) { return nil, nil }})
		result <- accepted{stream: stream, err: err}
	}()
	clientStream, _, err := client.Initiate(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle})
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-result
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	clientConn, err := NewSecureConn(clientStream, "cli_01", "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := NewSecureConn(serverResult.stream, "machine_01", "cli_01")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	defer serverConn.Close()
	payload := bytes.Repeat([]byte("p"), secureConnChunk*2+17)
	written := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(payload)
		written <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, received); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("write=%v payload_equal=%t", err, bytes.Equal(received, payload))
	}
	if err := serverConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := serverConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read deadline did not interrupt secure stream")
	}
}

func TestSecureConnHalfClosePreservesReverseTraffic(t *testing.T) {
	client, server, _ := wssPair(t, 4)
	initiator, responder, handle, prologue := testIdentities(t, relaynoise.CarrierWSS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type accepted struct {
		stream *SecureStream
		err    error
	}
	result := make(chan accepted, 1)
	go func() {
		stream, _, err := server.Accept(ctx, ResponderConfig{LocalStatic: responder, InitiatorPublic: public32(initiator), Prologue: prologue, Handle: handle, Authorize: func(context.Context, []byte) ([]byte, error) { return nil, nil }})
		result <- accepted{stream: stream, err: err}
	}()
	clientStream, _, err := client.Initiate(ctx, InitiatorConfig{LocalStatic: initiator, ResponderPublic: public32(responder), Prologue: prologue, Handle: handle})
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-result
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	clientConn, err := NewSecureConn(clientStream, "cli_01", "machine_01")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := NewSecureConn(serverResult.stream, "machine_01", "cli_01")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	request := []byte{0x00, 0xff, 0x80, 0x01}
	response := []byte{0xfe, 0x00, 0x7f, 0xff}
	if _, err := clientConn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if value, err := io.ReadAll(serverConn); err != nil || !bytes.Equal(value, request) {
		t.Fatalf("request=%x err=%v", value, err)
	}
	if _, err := serverConn.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if value, err := io.ReadAll(clientConn); err != nil || !bytes.Equal(value, response) {
		t.Fatalf("response=%x err=%v", value, err)
	}
}

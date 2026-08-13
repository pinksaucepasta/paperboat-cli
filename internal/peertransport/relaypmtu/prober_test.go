package relaypmtu

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"testing"
	"time"
)

func TestProberSendsAndVerifiesExactDatagram(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		frame := make([]byte, MaximumSize)
		n, remote, readErr := server.ReadFromUDP(frame)
		if readErr != nil {
			done <- readErr
			return
		}
		frame[5] = kindReply
		clear(frame[24:26])
		clear(frame[headerSize:n])
		mac := hmac.New(sha256.New, []byte("header.payload.signature"))
		_, _ = mac.Write(frame[:n-tagSize])
		copy(frame[n-tagSize:n], mac.Sum(nil))
		_, writeErr := server.WriteToUDP(frame[:n], remote)
		done <- writeErr
	}()
	prober, err := Open(context.Background(), "udp://"+server.LocalAddr().String(), "header.payload.signature", 1452)
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := prober.ProbePayload(ctx, 1280)
	if err != nil || !result.Supported || result.At.IsZero() {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProberRejectsInvalidConfiguration(t *testing.T) {
	for _, endpoint := range []string{"", "https://relay.example.test:3478", "udp://relay.example.test"} {
		if prober, err := Open(context.Background(), endpoint, "token", 1452); err == nil || prober != nil {
			t.Fatalf("endpoint %q accepted", endpoint)
		}
	}
}

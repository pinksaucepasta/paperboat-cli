package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
)

func TestPrivatePreviewRawApplicationWaitsForRemoteReadiness(t *testing.T) {
	client, host := net.Pipe()
	done := make(chan error, 1)
	dialed := make(chan [2]string, 1)
	go func() {
		done <- peerpreview.Serve(context.Background(), host, func(_ context.Context, network, address string) (net.Conn, error) {
			dialed <- [2]string{network, address}
			left, right := net.Pipe()
			go func() {
				defer right.Close()
				_, _ = io.Copy(io.Discard, right)
			}()
			return left, nil
		})
	}()
	if err := peerpreview.Open(context.Background(), client, 4321); err != nil {
		t.Fatal(err)
	}
	if value := <-dialed; value != [2]string{"tcp4", "127.0.0.1:4321"} {
		t.Fatalf("network=%q address=%q", value[0], value[1])
	}
	_ = client.Close()
	<-done
}

func TestPrivatePreviewPrefaceContainsOnlyVersionAndPort(t *testing.T) {
	client, host := net.Pipe()
	opened := make(chan error, 1)
	go func() { opened <- peerpreview.Open(context.Background(), client, 65535) }()
	var preface [7]byte
	if _, err := io.ReadFull(host, preface[:]); err != nil {
		t.Fatal(err)
	}
	if string(preface[:5]) != "PBPV\x01" || binary.BigEndian.Uint16(preface[5:]) != 65535 {
		t.Fatalf("preface=%x", preface)
	}
	if _, err := host.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = host.Close()
}

package windowsopenssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestQualificationSSHProtocolExecExitStatusAndPTY(t *testing.T) {
	clientSigner := testQualificationSigner(t)
	hostSigner := testQualificationSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var observed struct {
		sync.Mutex
		pty bool
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveQualificationSSHConnection(connection, hostSigner, clientSigner.PublicKey(), &observed)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := qualificationSSHClient(ctx, listener.Addr().String(), "paperboat", clientSigner, hostSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := qualificationSSHMarker(client, "output", "qualification-output", false); err != nil {
		t.Fatalf("exec qualification: %v", err)
	}
	if _, status, err := qualificationSSHExec(client, "exit-37", false); err != nil || status != qualificationExpectedExit {
		t.Fatalf("exit qualification status=%d err=%v", status, err)
	}
	if _, status, err := qualificationSSHExec(client, "pty-output", true); err != nil || status != 0 {
		t.Fatalf("PTY qualification status=%d err=%v", status, err)
	}
	observed.Lock()
	pty := observed.pty
	observed.Unlock()
	if !pty {
		t.Fatal("client did not request a PTY")
	}
	_ = listener.Close()
	<-serverDone
}

func TestQualificationSSHProtocolRejectsUnpinnedHostKey(t *testing.T) {
	clientSigner := testQualificationSigner(t)
	hostSigner := testQualificationSigner(t)
	wrongHostSigner := testQualificationSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			serveQualificationSSHConnection(connection, hostSigner, clientSigner.PublicKey(), nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if client, err := qualificationSSHClient(ctx, listener.Addr().String(), "paperboat", clientSigner, wrongHostSigner.PublicKey()); err == nil {
		client.Close()
		t.Fatal("unpinned host key was accepted")
	}
}

func testQualificationSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func serveQualificationSSHConnection(connection net.Conn, host ssh.Signer, client ssh.PublicKey, observed *struct {
	sync.Mutex
	pty bool
}) {
	defer connection.Close()
	config := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), client.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("client key is not authorized")
	}}
	config.AddHostKey(host)
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			requestedPTY := false
			for request := range requests {
				switch request.Type {
				case "pty-req":
					requestedPTY = true
					if observed != nil {
						observed.Lock()
						observed.pty = true
						observed.Unlock()
					}
					_ = request.Reply(true, nil)
				case "exec":
					var payload struct{ Command string }
					if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
						_ = request.Reply(false, nil)
						return
					}
					_ = request.Reply(true, nil)
					status := uint32(0)
					if payload.Command == "exit-37" {
						status = qualificationExpectedExit
					} else if requestedPTY || strings.Contains(payload.Command, "pty") {
						_, _ = channel.Write([]byte("qualification-pty\n"))
					} else {
						_, _ = channel.Write([]byte("qualification-output\n"))
					}
					_ = channel.CloseWrite()
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
					return
				default:
					_ = request.Reply(false, nil)
				}
			}
		}()
	}
}

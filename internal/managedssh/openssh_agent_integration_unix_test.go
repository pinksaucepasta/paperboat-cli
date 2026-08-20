//go:build darwin || linux

package managedssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestOpenSSHUsesPublicSelectorWithCredentialStoreBackedAgent(t *testing.T) {
	openSSH, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	home := openSSHTestHome(t)
	runtimeDirectory := shortRuntimeDirectory(t, "pb-ssh-openssh-")
	managedSigner, _ := testKey(t)
	service, err := StartAgentService(t.Context(), AgentServiceConfig{
		RuntimeDirectory: runtimeDirectory, Signer: managedSigner,
		MaxConnections: 4, IdleTimeout: 5 * time.Second, DelegateTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	publicLine := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(managedSigner.PublicKey())))
	if err := InstallManagedIdentityPublicKey(home, uint32(os.Getuid()), publicLine); err != nil {
		t.Fatal(err)
	}

	listener, serverDone := startManagedSSHAuthenticationServer(t, managedSigner.PublicKey())
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, openSSH,
		"-F", "/dev/null",
		"-o", "IdentityAgent="+service.Socket(),
		"-o", "IdentityFile="+ManagedIdentityPublicKeyPath(home),
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", strconv.Itoa(port), "paperboat@127.0.0.1", "managed-auth-canary",
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil || string(output) != "managed-auth-ok" {
		t.Fatalf("OpenSSH managed authentication output=%q error=%v stderr=%s", output, err, stderr.String())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := ProbeAgentIdentity(t.Context(), service.Socket(), sha256.Sum256(managedSigner.PublicKey().Marshal()), time.Second); err != nil {
		t.Fatalf("managed agent stopped after OpenSSH authentication: %v", err)
	}
}

func startManagedSSHAuthenticationServer(t *testing.T, allowed ssh.PublicKey) (net.Listener, <-chan error) {
	t.Helper()
	hostSigner, _ := testKey(t)
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unmanaged SSH identity")
		},
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		server, channels, requests, handshakeErr := ssh.NewServerConn(connection, config)
		if handshakeErr != nil {
			done <- handshakeErr
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			channel, channelRequests, channelErr := incoming.Accept()
			if channelErr != nil {
				done <- channelErr
				return
			}
			for request := range channelRequests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				_, _ = io.WriteString(channel, "managed-auth-ok")
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				_, _ = channel.SendRequest("exit-status", false, status)
				_ = channel.Close()
				done <- nil
				return
			}
		}
		done <- errors.New("OpenSSH session channel was not received")
	}()
	return listener, done
}

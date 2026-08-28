//go:build darwin || linux

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type localPeerTunnelSnapshotSource struct{}

func (localPeerTunnelSnapshotSource) Snapshot(context.Context) (localapi.Snapshot, error) {
	return localapi.Snapshot{}, nil
}

type localPeerTunnelBroker func(context.Context, localapi.Peer, localapi.PeerStreamRequest) (net.Conn, error)

func (b localPeerTunnelBroker) OpenPeerStream(ctx context.Context, peer localapi.Peer, request localapi.PeerStreamRequest) (net.Conn, error) {
	return b(ctx, peer, request)
}

func TestLocalPeerTunnelTerminalPreservesFramingAndWaitLifecycle(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "paperboat-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socket := root + "/peer.sock"
	remoteServer, remotePeer := net.Pipe()
	defer remotePeer.Close()
	releaseWait := make(chan struct{})
	requestSeen := make(chan localapi.PeerStreamRequest, 1)
	broker := localPeerTunnelBroker(func(_ context.Context, _ localapi.Peer, request localapi.PeerStreamRequest) (net.Conn, error) {
		if request.Consumer != "terminal" || request.OperationID != "session_1" {
			return nil, errors.New("unexpected terminal peer request")
		}
		requestSeen <- request
		client, bridge := net.Pipe()
		remote := &blockingWaitRemote{
			localPeerRemote: &localPeerRemote{Conn: remoteServer, runtimeVersion: "2026.08.27.65"},
			release:         releaseWait,
		}
		go func() { _ = ServeLocalPeerDebugConn(context.Background(), bridge, remote) }()
		return client, nil
	})
	server, err := localapi.NewServer(localapi.ServerConfig{
		SocketPath:  socket,
		OwnerUID:    os.Geteuid(),
		OwnerGID:    os.Getegid(),
		Source:      localPeerTunnelSnapshotSource{},
		PeerStreams: broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	t.Cleanup(func() {
		cancelServer()
		if err := <-serverDone; !errors.Is(err, context.Canceled) {
			t.Errorf("local API server error: %v", err)
		}
	})
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local API socket was not created")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := localapi.NewClient(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := LocalPeerTunnel{Client: client, Transport: TerminalTransportAuto}
	connection, err := tunnel.Dial(context.Background(), resolver.ConnectInfo{
		ProjectID:         "machine_1",
		MachineGeneration: 1,
		Terminal: &resolver.TerminalTarget{
			EnvironmentID: "environment_1",
			SessionID:     "session_1",
			Debug:         true,
			Auth: resolver.AuthTarget{
				Token:     "credential",
				ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if got := TerminalRuntimeVersion(connection); got != "2026.08.27.65" {
		t.Fatalf("runtime version=%q", got)
	}
	select {
	case request := <-requestSeen:
		if request.Consumer != "terminal" || request.OperationID != "session_1" {
			t.Fatalf("peer request consumer=%q operation=%q", request.Consumer, request.OperationID)
		}
		var payload localapi.PeerTerminalPayload
		if json.Unmarshal(request.Payload, &payload) != nil || !payload.Debug {
			t.Fatalf("peer terminal debug payload=%s", request.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal peer request was not observed")
	}

	waitDone := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, waitErr := connection.Wait()
		waitDone <- struct {
			code int
			err  error
		}{code: code, err: waitErr}
	}()
	select {
	case result := <-waitDone:
		t.Fatalf("terminal Wait returned before remote exit: code=%d err=%v", result.code, result.err)
	case <-time.After(20 * time.Millisecond):
	}

	if _, err := connection.Write([]byte("input")); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, len("input"))
	if _, err := io.ReadFull(remotePeer, input); err != nil || string(input) != "input" {
		t.Fatalf("remote input=%q err=%v", input, err)
	}
	go func() { _, _ = remotePeer.Write([]byte("output")) }()
	output := make([]byte, len("output"))
	if _, err := io.ReadFull(connection, output); err != nil || string(output) != "output" {
		t.Fatalf("terminal output=%q err=%v", output, err)
	}
	if err := connection.Resize(24, 80); err != nil {
		t.Fatal(err)
	}

	close(releaseWait)
	select {
	case result := <-waitDone:
		if result.err != nil || result.code != 0 {
			t.Fatalf("terminal Wait code=%d err=%v", result.code, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal Wait did not return after remote exit")
	}
}

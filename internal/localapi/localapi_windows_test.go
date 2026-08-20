//go:build windows

package localapi

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

type windowsSnapshotSource func(context.Context) (Snapshot, error)

func (f windowsSnapshotSource) Snapshot(ctx context.Context) (Snapshot, error) { return f(ctx) }

type windowsSnapshotWatcher func(context.Context, uint64) (Snapshot, error)

func (f windowsSnapshotWatcher) Watch(ctx context.Context, after uint64) (Snapshot, error) {
	return f(ctx, after)
}

type windowsWatchSource struct {
	windowsSnapshotSource
	windowsSnapshotWatcher
}

type windowsPeerBroker func(context.Context, Peer, PeerStreamRequest) (net.Conn, error)

func (f windowsPeerBroker) OpenPeerStream(ctx context.Context, peer Peer, request PeerStreamRequest) (net.Conn, error) {
	return f(ctx, peer, request)
}

type windowsFileBroker struct {
	remote   chan net.Conn
	released chan string
}

func (b windowsFileBroker) PrepareFileTransfer(context.Context, Peer, FileTransferKeyRequest) (FileTransferKeyResult, error) {
	return FileTransferKeyResult{PeerContext: []byte("peer-context"), Handle: "transferhandle"}, nil
}

func (b windowsFileBroker) OpenFileTransferStream(context.Context, Peer, string) (net.Conn, error) {
	local, remote := net.Pipe()
	b.remote <- remote
	return local, nil
}

func (b windowsFileBroker) ReleaseFileTransfer(_ Peer, handle string) error {
	b.released <- handle
	return nil
}

func TestWindowsLocalAPIPipeParitySnapshotWatchAndPeerStream(t *testing.T) {
	ownerSID := testCurrentSID(t)
	pipe := testPipePath(t)
	if !validPipePath(pipe) || !validSID(ownerSID) {
		t.Fatalf("invalid test identity: pipe=%q validPipe=%t SID=%q validSID=%t", pipe, validPipePath(pipe), ownerSID, validSID(ownerSID))
	}
	base := windowsValidSnapshot(1)
	var peersMu sync.Mutex
	var peers []Peer
	remoteStreams := make(chan net.Conn, 1)
	server, err := NewServer(ServerConfig{
		SocketPath: pipe,
		OwnerSID:   ownerSID,
		Source: windowsWatchSource{
			windowsSnapshotSource: func(context.Context) (Snapshot, error) { return base, nil },
			windowsSnapshotWatcher: func(ctx context.Context, after uint64) (Snapshot, error) {
				if after != 1 {
					return Snapshot{}, errors.New("unexpected watch cursor")
				}
				return windowsValidSnapshot(2), nil
			},
		},
		Authorize: func(peer Peer) bool {
			peersMu.Lock()
			defer peersMu.Unlock()
			peers = append(peers, peer)
			return peer.SID == ownerSID && peer.PID == os.Getpid()
		},
		PeerStreams: windowsPeerBroker(func(context.Context, Peer, PeerStreamRequest) (net.Conn, error) {
			local, remote := net.Pipe()
			remoteStreams <- remote
			return local, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	client, err := waitForWindowsClient(pipe, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := client.Snapshot(context.Background())
	if err != nil || snapshot.Generation != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	updates, watchErrors := client.Watch(watchCtx, 1)
	select {
	case update := <-updates:
		if update.Generation != 2 {
			t.Fatalf("watch generation=%d", update.Generation)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not return a snapshot")
	}
	cancelWatch()
	select {
	case <-watchErrors:
	case <-time.After(time.Second):
		t.Fatal("watch did not terminate after cancellation")
	}

	request, err := NewPeerStreamRequest("machine_1", "environment_1", 1, "exec", "operation_1", "credential", time.Now().Add(time.Minute), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenPeerStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	remote := <-remoteStreams
	defer remote.Close()
	defer stream.Close()
	if _, err := stream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, len("request"))
	if _, err := remote.Read(read); err != nil || string(read) != "request" {
		t.Fatalf("remote read=%q err=%v", read, err)
	}
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	read = make([]byte, len("response"))
	if _, err := stream.Read(read); err != nil || string(read) != "response" {
		t.Fatalf("stream read=%q err=%v", read, err)
	}
	peersMu.Lock()
	defer peersMu.Unlock()
	if len(peers) < 3 {
		t.Fatalf("authenticated peer calls=%d", len(peers))
	}
	for _, peer := range peers {
		if peer.SID != ownerSID || peer.PID != os.Getpid() {
			t.Fatalf("peer=%#v", peer)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func TestWindowsPipeContractRejectsInvalidNamesAndUsesExactProtectedDACL(t *testing.T) {
	ownerSID := testCurrentSID(t)
	if got, want := pipeSecurityDescriptor(ownerSID), "D:P(A;;GWGR;;;SY)(A;;GWGR;;;"+ownerSID+")"; got != want {
		t.Fatalf("DACL=%q want=%q", got, want)
	}
	for _, path := range []string{"", `\\server\pipe\paperboat`, `\\.\pipe\paperboat/other`, `\\.\pipe\bad\nname`} {
		if _, err := NewClient(path, time.Second); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("NewClient(%q) err=%v", path, err)
		}
	}
	if _, err := NewServer(ServerConfig{SocketPath: testPipePath(t), OwnerSID: "not-a-sid", Source: windowsSnapshotSource(func(context.Context) (Snapshot, error) { return windowsValidSnapshot(1), nil })}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid SID err=%v", err)
	}
	if _, err := windowsPeerIdentity(struct{ net.Conn }{}); !errors.Is(err, ErrPermission) {
		t.Fatalf("non-pipe peer err=%v", err)
	}
}

func TestWindowsNamedPipePreservesFileTransferUpgradeAndLeaseCleanup(t *testing.T) {
	ownerSID := testCurrentSID(t)
	pipe := testPipePath(t)
	broker := windowsFileBroker{remote: make(chan net.Conn, 1), released: make(chan string, 1)}
	server, err := NewServer(ServerConfig{
		SocketPath:    pipe,
		OwnerSID:      ownerSID,
		Source:        windowsSnapshotSource(func(context.Context) (Snapshot, error) { return windowsValidSnapshot(1), nil }),
		FileTransfers: broker,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	client, err := waitForWindowsClient(pipe, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := FileTransferKeyRequest{
		Schema:            FileTransferKeySchemaV1,
		MachineID:         "machine_1",
		EnvironmentID:     "environment_1",
		MachineGeneration: 1,
		Transport:         "q",
		OperationID:       "operation_1",
		TransferID:        "transfer_1",
		Generation:        1,
		ExpiresAt:         time.Now().Add(time.Minute),
		Material:          make([]byte, 45),
	}
	lease, err := client.PrepareFileTransfer(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(lease.PeerContext) != "peer-context" || lease.Handle != "transferhandle" {
		t.Fatalf("lease=%#v", lease)
	}
	stream, err := client.OpenFileTransferStream(context.Background(), lease.Handle)
	if err != nil {
		t.Fatal(err)
	}
	remote := <-broker.remote
	defer remote.Close()
	defer stream.Close()
	if _, err := stream.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, len("upload"))
	if _, err := remote.Read(read); err != nil || string(read) != "upload" {
		t.Fatalf("remote read=%q err=%v", read, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case handle := <-broker.released:
		if handle != lease.Handle {
			t.Fatalf("released handle=%q", handle)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("file transfer lease was not released")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server err=%v", err)
	}
}

func testCurrentSID(t *testing.T) string {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current token SID: %v", err)
	}
	return sid
}

func testPipePath(t *testing.T) string {
	t.Helper()
	return `\\.\pipe\paperboat-localapi-test-` + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func waitForWindowsClient(path string, timeout time.Duration) (*Client, error) {
	deadline := time.Now().Add(timeout)
	for {
		client, err := NewClient(path, timeout)
		if err == nil {
			if _, err = client.Snapshot(context.Background()); err == nil {
				return client, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func windowsValidSnapshot(generation uint64) Snapshot {
	return Snapshot{Schema: SnapshotSchemaV1, Generation: generation, ObservedAt: time.Now().UTC(), DaemonState: "ready"}
}

//go:build windows

package localapi

import (
	"context"
	"net"
)

// ObservationSink is declared in the Unix local API server on Unix systems.
// Keep the data contract available to the cross-platform observation store;
// the Windows named-pipe server will implement it when Windows host mode is
// enabled.
type ObservationSink interface {
	PublishObservation(context.Context, Peer, TransportObservation) error
}

type SnapshotSource interface {
	Snapshot(context.Context) (Snapshot, error)
}

type SnapshotWatcher interface {
	Watch(context.Context, uint64) (Snapshot, error)
}

type CompletionSource interface {
	Completions(context.Context) (CompletionSnapshot, error)
}

type PeerStreamBroker interface {
	OpenPeerStream(context.Context, Peer, PeerStreamRequest) (net.Conn, error)
}

type PeerProbeBroker interface {
	ProbePeer(context.Context, Peer, PeerStreamRequest) (PeerProbeResult, error)
}

type FileTransferBroker interface {
	PrepareFileTransfer(context.Context, Peer, FileTransferKeyRequest) (FileTransferKeyResult, error)
	OpenFileTransferStream(context.Context, Peer, string) (net.Conn, error)
	ReleaseFileTransfer(Peer, string) error
}

type StaleSocketAuthority interface {
	CanRemoveStaleSocket(context.Context, string) bool
}

type ReadAuthorizer func(Peer) bool

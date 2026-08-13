package localdaemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

type daemonTransferLease struct {
	peer    localapi.Peer
	expires time.Time
	opener  tunnel.DirectTransferStreamOpener
	closer  io.Closer
}

type transferLeaseCloser struct {
	closer io.Closer
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (c *transferLeaseCloser) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.cancel()
		c.err = c.closer.Close()
	})
	return c.err
}

// FileTransferBroker keeps direct file carriers inside the daemon and gives a
// local process only a PID-bound capability for opening application streams.
type FileTransferBroker struct {
	tunnel transferKeyPreparer
	now    func() time.Time

	mu     sync.Mutex
	closed bool
	leases map[string]daemonTransferLease
}

type transferKeyPreparer interface {
	PrepareTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, http.RoundTripper, error)
}

func NewFileTransferBroker(peerTunnel transferKeyPreparer) (*FileTransferBroker, error) {
	if peerTunnel == nil {
		return nil, ErrInvalidInventoryConfig
	}
	return &FileTransferBroker{tunnel: peerTunnel, now: time.Now, leases: make(map[string]daemonTransferLease)}, nil
}

func (b *FileTransferBroker) PrepareFileTransfer(ctx context.Context, peer localapi.Peer, request localapi.FileTransferKeyRequest) (localapi.FileTransferKeyResult, error) {
	if b == nil || ctx == nil || peer.PID <= 0 || request.Validate(b.now().UTC()) != nil {
		return localapi.FileTransferKeyResult{}, ErrInvalidInventoryConfig
	}
	material, err := transfercrypto.ParseKeyMaterial(request.Material)
	if err != nil {
		return localapi.FileTransferKeyResult{}, err
	}
	defer material.Destroy()
	info := resolver.ConnectInfo{
		TargetKind: "machine", ProjectID: request.MachineID, MachineGeneration: request.MachineGeneration, Transport: request.Transport,
		Terminal: &resolver.TerminalTarget{EnvironmentID: request.EnvironmentID},
	}
	binding := transfercrypto.KeyControlBinding{OperationID: request.OperationID, TransferID: request.TransferID, Generation: request.Generation, ExpiresAt: request.ExpiresAt}
	leaseCtx, cancelLease := context.WithCancel(context.Background())
	stopSetupCancel := context.AfterFunc(ctx, cancelLease)
	peerCtx, direct, err := b.tunnel.PrepareTransferKey(leaseCtx, info, binding, material)
	if err != nil {
		stopSetupCancel()
		cancelLease()
		return localapi.FileTransferKeyResult{}, err
	}
	if !stopSetupCancel() || ctx.Err() != nil || leaseCtx.Err() != nil {
		cancelLease()
		if closer, ok := direct.(io.Closer); ok {
			_ = closer.Close()
		}
		return localapi.FileTransferKeyResult{}, context.Canceled
	}
	encoded, err := peerCtx.MarshalBinary()
	if err != nil {
		cancelLease()
		if closer, ok := direct.(io.Closer); ok {
			_ = closer.Close()
		}
		return localapi.FileTransferKeyResult{}, err
	}
	result := localapi.FileTransferKeyResult{PeerContext: encoded}
	if direct == nil {
		cancelLease()
		return result, nil
	}
	opener, ok := direct.(tunnel.DirectTransferStreamOpener)
	closer, closeOK := direct.(io.Closer)
	if !ok || !closeOK {
		cancelLease()
		if closeOK {
			_ = closer.Close()
		}
		return localapi.FileTransferKeyResult{}, errors.New("direct file transfer carrier lacks stream ownership")
	}
	handle, err := newTransferHandle()
	if err != nil {
		cancelLease()
		_ = closer.Close()
		return localapi.FileTransferKeyResult{}, err
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancelLease()
		_ = closer.Close()
		return localapi.FileTransferKeyResult{}, net.ErrClosed
	}
	b.leases[handle] = daemonTransferLease{peer: peer, expires: request.ExpiresAt, opener: opener, closer: &transferLeaseCloser{closer: closer, cancel: cancelLease}}
	b.mu.Unlock()
	result.Handle = handle
	return result, nil
}

func (b *FileTransferBroker) OpenFileTransferStream(ctx context.Context, peer localapi.Peer, handle string) (net.Conn, error) {
	b.mu.Lock()
	lease, ok := b.leases[handle]
	if ok && (!samePeer(lease.peer, peer) || !lease.expires.After(b.now().UTC())) {
		ok = false
	}
	b.mu.Unlock()
	if !ok {
		return nil, localapi.ErrPermission
	}
	return lease.opener.OpenTransferStream(ctx)
}

func (b *FileTransferBroker) ReleaseFileTransfer(peer localapi.Peer, handle string) error {
	b.mu.Lock()
	lease, ok := b.leases[handle]
	if ok && samePeer(lease.peer, peer) {
		delete(b.leases, handle)
	} else {
		ok = false
	}
	b.mu.Unlock()
	if !ok {
		return localapi.ErrPermission
	}
	return lease.closer.Close()
}

func (b *FileTransferBroker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	leases := b.leases
	b.leases = make(map[string]daemonTransferLease)
	b.mu.Unlock()
	var result error
	for _, lease := range leases {
		result = errors.Join(result, lease.closer.Close())
	}
	return result
}

func samePeer(left, right localapi.Peer) bool {
	return left.UID == right.UID && left.GID == right.GID && left.PID == right.PID
}

func newTransferHandle() (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

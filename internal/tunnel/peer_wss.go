package tunnel

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/nativepeer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peersession"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

var nativePeerStreamIDs = [...]string{"native-control", "native-input", "native-output"}

func newPeerRelayHealthConnection(connection *relaycarrier.Connection, authority peersession.Authority) (*relaycarrier.HealthConnection, relaycarrier.InitiatorConfig, error) {
	streamAuthority, err := authority.Initiator("native-health")
	if err != nil {
		return nil, relaycarrier.InitiatorConfig{}, err
	}
	initial, err := relaycarrier.PeerInitiatorConfig(streamAuthority, connection.Carrier(), "native-health", nil)
	if err != nil {
		return nil, relaycarrier.InitiatorConfig{}, err
	}
	source := relaycarrier.HealthConfigSourceFunc(func(_ context.Context, handle [16]byte) (relaycarrier.InitiatorConfig, error) {
		periodicAuthority := streamAuthority
		periodicAuthority.Handle = handle
		return relaycarrier.PeerInitiatorConfig(periodicAuthority, connection.Carrier(), "native-health", nil)
	})
	health, err := relaycarrier.NewHealthConnection(connection, source)
	return health, initial, err
}

func admitPeerRelayHealth(ctx context.Context, health *relaycarrier.HealthConnection, initial relaycarrier.InitiatorConfig) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	return health.AdmitInitialRelayHealth(ctx, initial, nonce)
}

type peerWSSNativeStreamGroup struct {
	initiator nativepeer.Initiator
	mu        sync.Mutex
	next      int
}

func (g *peerWSSNativeStreamGroup) OpenStream(ctx context.Context) (nativeStream, error) {
	if g == nil {
		return nil, nativepeer.ErrInvalid
	}
	g.mu.Lock()
	if g.next >= len(nativePeerStreamIDs) {
		g.mu.Unlock()
		return nil, nativepeer.ErrInvalid
	}
	streamID := nativePeerStreamIDs[g.next]
	g.next++
	g.mu.Unlock()
	connection, err := g.initiator.Open(ctx, streamID)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (g *peerWSSNativeStreamGroup) Close() error {
	if g == nil {
		return nil
	}
	return g.initiator.Close()
}

// AuthenticatePeerWSS runs the existing native terminal authentication over
// three independently authenticated Noise streams carried by one WSS relay.
func AuthenticatePeerWSS(ctx context.Context, initiator nativepeer.Initiator, target *resolver.TerminalTarget) (*nativeMessageConnection, error) {
	return authenticatePeerRelay(ctx, initiator, target, "WSS")
}

func authenticatePeerRelay(ctx context.Context, initiator nativepeer.Initiator, target *resolver.TerminalTarget, transport string) (*nativeMessageConnection, error) {
	if initiator.Connection == nil || target == nil {
		return nil, nativepeer.ErrInvalid
	}
	group := &peerWSSNativeStreamGroup{initiator: initiator}
	message, err := authenticateNativeStreamGroup(ctx, group, target, transport)
	if err != nil {
		return nil, errors.Join(err, group.Close())
	}
	return message, nil
}

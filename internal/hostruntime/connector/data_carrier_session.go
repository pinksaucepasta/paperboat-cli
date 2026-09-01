package connector

import (
	"context"
	"errors"
	"sync"
)

var ErrDataCarrierSessionSource = errors.New("invalid data carrier session source")

// DataCarrierIdentitySource is the live control-session identity boundary.
// Implementations must return the identity authenticated for the current
// connector process, rather than reconstructing session or generation fields
// from durable tunnel state.
type DataCarrierIdentitySource func(context.Context) (DataCarrierIdentity, error)

// DataCarrierSessionSource supplies the exact identity and transport dialer
// used to stage a carrier pool. The source itself does not activate a pool;
// callers use PrepareDataCarrierRequest and promote it only after edge, route,
// and origin readiness has been observed.
type DataCarrierSessionSource struct {
	Identity       DataCarrierIdentity
	IdentitySource DataCarrierIdentitySource
	Config         DataCarrierPoolConfig
	Dialer         DataCarrierDialer
	state          *dataCarrierSessionIdentityState
}

type dataCarrierSessionIdentityState struct {
	mu   sync.Mutex
	base DataCarrierIdentity
	last DataCarrierIdentity
}

// NewDataCarrierSessionSource constructs a source for an already authenticated
// connector-v1 session. IdentitySource may be supplied when the process can
// rotate its live session; when present it is authoritative over Identity.
func NewDataCarrierSessionSource(identity DataCarrierIdentity, config DataCarrierPoolConfig, dialer DataCarrierDialer) (DataCarrierSessionSource, error) {
	if err := identity.validate(); err != nil || dialer == nil {
		return DataCarrierSessionSource{}, ErrDataCarrierSessionSource
	}
	if config.Session != (DataCarrierIdentity{}) && !sameDataCarrierBaseIdentity(config.Session, identity) {
		return DataCarrierSessionSource{}, ErrDataCarrierSessionSource
	}
	config = config.withDefaults()
	config.Session = identity
	if err := config.Validate(); err != nil {
		return DataCarrierSessionSource{}, err
	}
	config.Session = DataCarrierIdentity{}
	return DataCarrierSessionSource{
		Identity: identity, Config: config, Dialer: dialer,
		state: &dataCarrierSessionIdentityState{base: identity, last: identity},
	}, nil
}

// PrepareDataCarrier returns the narrow request consumed by the staged pool
// primitive. It performs no network work, so a caller can validate and stage
// state before deciding when to connect.
func (s DataCarrierSessionSource) PrepareDataCarrier(ctx context.Context) (DataCarrierPrepareRequest, error) {
	if ctx == nil {
		return DataCarrierPrepareRequest{}, ErrDataCarrierSessionSource
	}
	if s.state == nil {
		return DataCarrierPrepareRequest{}, ErrDataCarrierSessionSource
	}
	identity := s.Identity
	if s.IdentitySource != nil {
		var err error
		identity, err = s.IdentitySource(ctx)
		if err != nil {
			return DataCarrierPrepareRequest{}, err
		}
	}
	if err := identity.validate(); err != nil || s.Dialer == nil {
		return DataCarrierPrepareRequest{}, ErrDataCarrierSessionSource
	}
	s.state.mu.Lock()
	if !sameDataCarrierBaseIdentity(s.state.base, identity) || identity.ProcessGeneration < s.state.last.ProcessGeneration || identity.Generation < s.state.last.Generation {
		s.state.mu.Unlock()
		return DataCarrierPrepareRequest{}, ErrDataCarrierSessionSource
	}
	s.state.last = identity
	s.state.mu.Unlock()
	config := s.Config
	config.Session = identity
	if err := config.Validate(); err != nil {
		return DataCarrierPrepareRequest{}, err
	}
	return DataCarrierPrepareRequest{Identity: identity, Config: config, Dialer: s.Dialer}, nil
}

// Prepare connects and authenticates a staged pool. It is a convenience for
// adapters that do not need to inspect the request before calling the pool.
func (s DataCarrierSessionSource) Prepare(ctx context.Context) (*PreparedDataCarrier, error) {
	request, err := s.PrepareDataCarrier(ctx)
	if err != nil {
		return nil, err
	}
	return PrepareDataCarrierRequest(ctx, request)
}

// NewNetworkDataCarrierSessionSource binds the source to the production TCP
// mTLS and native-QUIC endpoint dialers. The endpoint callbacks remain the
// certificate-to-session authorization boundary.
func NewNetworkDataCarrierSessionSource(identity DataCarrierIdentity, config DataCarrierPoolConfig, endpoints NetworkDialerConfig) (DataCarrierSessionSource, error) {
	return NewDataCarrierSessionSource(identity, config, NewNetworkDialer(endpoints))
}

func sameDataCarrierBaseIdentity(left, right DataCarrierIdentity) bool {
	return left.AccountID == right.AccountID && left.HostID == right.HostID && left.TunnelID == right.TunnelID && left.ConnectorID == right.ConnectorID
}

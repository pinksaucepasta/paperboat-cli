package tunnelenrollment

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connectorrotation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/tunnelmanager"
)

// productionRotationRuntime owns one old-credential rotation epoch. It keeps
// the old assembly serving while a replacement process establishes a new
// signed control session, applies the authoritative snapshot, and activates
// its carrier. Only the server's revoke message retires the old assembly.
type productionRotationRuntime struct {
	source  *HTTPSProductionAssemblySource
	request ActivationRequest
	manager *connectorrotation.Manager
	keys    *rotationCredentialStore

	mu              sync.Mutex
	current         *tunnelmanager.ProductionAssembly
	install         *connectorprotocol.CredentialRotationInstall
	replacementReq  ActivationRequest
	replacement     *tunnelmanager.ProductionAssembly
	replacementDone chan struct{}
	replacementErr  error
	revokeCommitted bool
	drainingActive  tunnelmanager.Active
	drainingCarrier *connector.ActiveDataCarrier
	oldCarrier      func(*tunnelmanager.ProductionAssembly) (tunnelmanager.Active, *connector.ActiveDataCarrier, error)
	replacementID   func(*tunnelmanager.ProductionAssembly) (string, bool)
	shutdownOld     func(context.Context, *tunnelmanager.ProductionAssembly) error
}

type rotationCredentialStore struct {
	store        *FileCredentialStore
	oldReference string
	mu           sync.Mutex
	deleteOld    bool
}

func (s *rotationCredentialStore) Put(ctx context.Context, private ed25519.PrivateKey) (connectorrotation.KeyReference, error) {
	return s.store.Put(ctx, private)
}

func (s *rotationCredentialStore) Sign(ctx context.Context, reference string, payload []byte) ([]byte, error) {
	return s.store.Sign(ctx, reference, payload)
}

func (s *rotationCredentialStore) Delete(ctx context.Context, reference string) error {
	if reference != s.oldReference {
		return s.store.Delete(ctx, reference)
	}
	s.mu.Lock()
	s.deleteOld = true
	s.mu.Unlock()
	return nil
}

func (s *rotationCredentialStore) commitDelete(ctx context.Context) error {
	s.mu.Lock()
	wanted := s.deleteOld
	s.mu.Unlock()
	if !wanted {
		return ErrConflict
	}
	return s.store.Delete(ctx, s.oldReference)
}

func (s *HTTPSProductionAssemblySource) rotationFor(request ActivationRequest) (*productionRotationRuntime, error) {
	if s == nil || !validActivationRequest(request) {
		return nil, ErrInvalid
	}
	key := activationBindingKey(request)
	s.mu.Lock()
	if current := s.rotations[key]; current != nil {
		s.mu.Unlock()
		return current, nil
	}
	credentials := s.credentials
	started, closed := s.started, s.closed
	s.mu.Unlock()
	if credentials == nil || !started || closed {
		return nil, ErrUnavailable
	}
	journal, err := connectorrotation.OpenFileJournal(filepath.Join(s.stateRoot, "tunnel-connectors", request.ConnectorID, "rotation-"+strconv.FormatUint(request.CredentialGeneration, 10)+".json"))
	if err != nil {
		return nil, err
	}
	keys := &rotationCredentialStore{store: credentials, oldReference: request.CredentialReference}
	runtime := &productionRotationRuntime{source: s, request: request, keys: keys}
	manager, err := connectorrotation.New(connectorrotation.Config{
		AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID, HostID: request.HostID,
		OldCredentialReference: request.CredentialReference, OldIdentityKeyID: request.CredentialKeyID,
		OldIdentityThumbprint: request.CredentialThumbprint, OldCredentialGeneration: request.CredentialGeneration,
		KeyStore: keys, Journal: journal, Installer: runtime, Clock: s.clock,
	})
	if err != nil {
		return nil, err
	}
	runtime.manager = manager
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.rotations[key]; current != nil {
		return current, nil
	}
	s.rotations[key] = runtime
	return runtime, nil
}

func (r *productionRotationRuntime) bind(assembly *tunnelmanager.ProductionAssembly) error {
	if r == nil || assembly == nil || assembly.Control == nil {
		return ErrActivation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil && r.current != assembly {
		return ErrConflict
	}
	r.current = assembly
	return nil
}

func (r *productionRotationRuntime) Install(ctx context.Context, install connectorprotocol.CredentialRotationInstall) error {
	if r == nil || ctx == nil || install.Validate(r.source.clock.Now().UTC()) != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.install != nil {
		if !sameRotationInstall(*r.install, install) {
			r.mu.Unlock()
			return ErrConflict
		}
		r.mu.Unlock()
		return nil
	}
	record, ok := r.manager.Record()
	if !ok || record.NewCredentialGeneration != install.NewCredentialGeneration || record.NewKey.Reference != install.NewCredentialReference || record.NewKey.KeyID != install.NewIdentityKeyID || record.NewKey.Thumbprint != install.NewIdentityKeyThumbprint {
		r.mu.Unlock()
		return ErrConflict
	}
	next := ActivationRequest{
		AccountID: r.request.AccountID, TunnelID: r.request.TunnelID, HostID: r.request.HostID,
		ConnectorID: r.request.ConnectorID, OperationID: install.OperationID, StableEndpointID: r.request.StableEndpointID,
		CredentialReference: record.NewKey.Reference, CredentialKeyID: record.NewKey.KeyID,
		CredentialThumbprint: record.NewKey.Thumbprint, CredentialPublicKey: append([]byte(nil), record.NewKey.PublicKey...),
		CredentialGeneration: install.NewCredentialGeneration, ProcessGeneration: install.ReplacementProcessGeneration,
	}
	copy := install
	r.install = &copy
	r.replacementReq = next
	r.replacementDone = make(chan struct{})
	done := r.replacementDone
	r.mu.Unlock()
	go r.startReplacement(next, done)
	return nil
}

func (r *productionRotationRuntime) startReplacement(request ActivationRequest, done chan struct{}) {
	ctx := r.source.lifecycleContext()
	var assembly *tunnelmanager.ProductionAssembly
	var result error
	if ctx == nil {
		result = ErrUnavailable
	} else {
		signer := func(signCtx context.Context, payload []byte) ([]byte, error) {
			return r.source.credentials.Sign(signCtx, request.CredentialReference, payload)
		}
		var config tunnelmanager.ProductionAssemblyConfig
		config, result = r.source.resolveProductionAssembly(ctx, request, signer, r)
		if result == nil {
			assembly, _, result = tunnelmanager.OpenProductionAssembly(config)
		}
		if result == nil {
			result = r.source.bindReplacementProductionAssembly(request, assembly, r)
		}
		if result == nil {
			result = assembly.Start(ctx)
		}
	}
	r.mu.Lock()
	if result != nil && assembly != nil {
		_ = assembly.Shutdown(context.Background())
		assembly = nil
	}
	r.replacement = assembly
	r.replacementErr = result
	close(done)
	r.mu.Unlock()
}

func (r *productionRotationRuntime) WaitReplacementReady(ctx context.Context, install connectorprotocol.CredentialRotationInstall) (connectorrotation.ReplacementReadiness, error) {
	if r == nil || ctx == nil {
		return connectorrotation.ReplacementReadiness{}, ErrInvalid
	}
	r.mu.Lock()
	needsInstall := r.install == nil
	r.mu.Unlock()
	if needsInstall {
		if err := r.Install(ctx, install); err != nil {
			return connectorrotation.ReplacementReadiness{}, err
		}
	}
	r.mu.Lock()
	if r.install == nil || !sameRotationInstall(*r.install, install) || r.replacementDone == nil {
		r.mu.Unlock()
		return connectorrotation.ReplacementReadiness{}, ErrConflict
	}
	done := r.replacementDone
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return connectorrotation.ReplacementReadiness{}, ctx.Err()
	}
	r.mu.Lock()
	assembly, replacementErr := r.replacement, r.replacementErr
	r.mu.Unlock()
	if replacementErr != nil || assembly == nil || assembly.Control == nil || assembly.Manager == nil || assembly.Manager.Manager == nil {
		return connectorrotation.ReplacementReadiness{}, errors.Join(ErrActivation, replacementErr)
	}
	for {
		session := assembly.Control.Session()
		active, activeOK := assembly.Manager.Manager.ActiveForTunnel(r.request.TunnelID)
		welcome, welcomeOK := assembly.Control.Welcome()
		if session != nil && session.State() == connectorprotocol.SessionReady && activeOK && active != nil && active.ConnectorID() == r.request.ConnectorID && welcomeOK {
			return connectorrotation.ReplacementReadiness{
				Session: session, NegotiatedCapabilities: append([]string(nil), welcome.Capabilities...), SessionID: welcome.SessionID,
				ProcessGeneration: r.replacementReq.ProcessGeneration, ConfigGeneration: active.Generation(), ConfigContentHash: active.ContentHash(),
				EdgeReady: true, RouteReady: true, OriginReady: true,
			}, nil
		}
		select {
		case <-ctx.Done():
			return connectorrotation.ReplacementReadiness{}, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (r *productionRotationRuntime) Revoke(ctx context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	if r == nil || ctx == nil || revoke.Validate(r.source.clock.Now().UTC()) != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.install == nil || r.replacement == nil || r.replacement.Control == nil && r.replacementID == nil || r.replacementErr != nil || revoke.OperationID != r.install.OperationID || revoke.NewCredentialGeneration != r.replacementReq.CredentialGeneration || revoke.ProcessGeneration != r.replacementReq.ProcessGeneration {
		r.mu.Unlock()
		return ErrConflict
	}
	welcomeSession := ""
	ok := false
	if r.replacementID != nil {
		welcomeSession, ok = r.replacementID(r.replacement)
	} else {
		var welcome connectorprotocol.Welcome
		welcome, ok = r.replacement.Control.Welcome()
		welcomeSession = welcome.SessionID
	}
	if !ok || welcomeSession != revoke.SessionID {
		r.mu.Unlock()
		return ErrConflict
	}
	if r.drainingActive != nil {
		r.mu.Unlock()
		return nil
	}
	current := r.current
	var active tunnelmanager.Active
	var carrier *connector.ActiveDataCarrier
	var err error
	if r.oldCarrier != nil {
		active, carrier, err = r.oldCarrier(current)
	} else {
		active, carrier, err = exactAssemblyCarrier(current, r.request.TunnelID, r.request.ConnectorID)
	}
	if err != nil {
		r.mu.Unlock()
		return err
	}
	if err := carrier.BeginDrain(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.drainingActive, r.drainingCarrier = active, carrier
	r.mu.Unlock()
	return nil
}

// PrepareRevoke runs before the revoked acknowledgement is written. The
// enrollment journal is fsynced to the new reference before the deferred old
// key deletion, so every crash window restarts on an accepted credential.
func (r *productionRotationRuntime) PrepareRevoke(ctx context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	if err := r.Revoke(ctx, revoke); err != nil {
		return err
	}
	r.mu.Lock()
	if r.revokeCommitted {
		r.mu.Unlock()
		return nil
	}
	next := r.replacementReq
	r.mu.Unlock()
	if err := r.source.credentials.promoteCredential(r.request.TunnelID, r.request, next); err != nil {
		return err
	}
	if err := r.keys.commitDelete(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	r.revokeCommitted = true
	r.mu.Unlock()
	return nil
}

// CommitRevoke runs only after the terminal acknowledgement has been written.
// It boundedly drains and closes the exact old assembly and surfaces failure
// to the production control supervisor.
func (r *productionRotationRuntime) CommitRevoke(ctx context.Context, revoke connectorprotocol.CredentialRotationRevoke) error {
	if r == nil || ctx == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	if !r.revokeCommitted || r.drainingActive == nil || r.drainingCarrier == nil {
		r.mu.Unlock()
		return ErrConflict
	}
	current, replacement := r.current, r.replacement
	r.current = replacement
	r.mu.Unlock()
	if current == nil || current == replacement {
		return nil
	}
	deadline := revoke.Deadline
	maximum := time.Now().Add(15 * time.Second)
	if deadline.IsZero() || deadline.After(maximum) {
		deadline = maximum
	}
	shutdownContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if r.shutdownOld != nil {
		return r.shutdownOld(shutdownContext, current)
	}
	return current.Shutdown(shutdownContext)
}

func exactAssemblyCarrier(assembly *tunnelmanager.ProductionAssembly, tunnelID, connectorID string) (tunnelmanager.Active, *connector.ActiveDataCarrier, error) {
	if assembly == nil || assembly.Manager == nil || assembly.Manager.Manager == nil {
		return nil, nil, ErrUnavailable
	}
	active, ok := assembly.Manager.Manager.ActiveForTunnel(tunnelID)
	if !ok || active == nil || active.ConnectorID() != connectorID {
		return nil, nil, ErrUnavailable
	}
	provider, ok := active.(tunnelmanager.ActiveCarrierProvider)
	if !ok || provider.ActiveDataCarrier() == nil {
		return nil, nil, ErrUnavailable
	}
	return active, provider.ActiveDataCarrier(), nil
}

// RejoinAfterRevoke forces the replacement control loop to authenticate again
// after the server has observed the revoked acknowledgement. Its reconnect
// factory then selects the new credential's own rotation journal.
func (r *productionRotationRuntime) RejoinAfterRevoke() bool { return true }

func (r *productionRotationRuntime) isCommitted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revokeCommitted
}

func (r *productionRotationRuntime) shutdown(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nil
	}
	r.mu.Lock()
	assemblies := []*tunnelmanager.ProductionAssembly{r.current, r.replacement}
	r.current, r.replacement = nil, nil
	r.mu.Unlock()
	var result error
	seen := map[*tunnelmanager.ProductionAssembly]struct{}{}
	for _, assembly := range assemblies {
		if assembly == nil {
			continue
		}
		if _, ok := seen[assembly]; ok {
			continue
		}
		seen[assembly] = struct{}{}
		result = errors.Join(result, assembly.Shutdown(ctx))
	}
	return result
}

func (s *HTTPSProductionAssemblySource) lifecycleContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.closed {
		return nil
	}
	return s.lifetime
}

func sameRotationInstall(a, b connectorprotocol.CredentialRotationInstall) bool {
	return a.AccountID == b.AccountID && a.TunnelID == b.TunnelID && a.OperationID == b.OperationID && a.ConnectorID == b.ConnectorID && a.HostID == b.HostID && a.SessionID == b.SessionID && a.ProcessGeneration == b.ProcessGeneration && a.TargetSetHash == b.TargetSetHash && a.OldCredentialGeneration == b.OldCredentialGeneration && a.NewCredentialGeneration == b.NewCredentialGeneration && a.NewIdentityKeyID == b.NewIdentityKeyID && a.NewIdentityKeyThumbprint == b.NewIdentityKeyThumbprint && a.NewPublicKey == b.NewPublicKey && a.NewCredentialReference == b.NewCredentialReference && a.ChallengeNonce == b.ChallengeNonce && a.OverlapUntil.Equal(b.OverlapUntil) && a.NewCredentialValidUntil.Equal(b.NewCredentialValidUntil) && a.ReplacementProcessGeneration == b.ReplacementProcessGeneration
}

var _ connectorrotation.Installer = (*productionRotationRuntime)(nil)
var _ connectorrotation.ReadinessSource = (*productionRotationRuntime)(nil)

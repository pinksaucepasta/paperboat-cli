package preview

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
)

func TestAttachmentPreviewCarrierProviderReusesOneHubPerActiveCarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	source := newProviderSessionSource(AttachmentSession{Active: pair.active, Identity: identity})
	provider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{
		Sessions: source, RunContext: ctx, QueueDepth: 2,
		OriginDial: func(context.Context, LeaseTarget) (io.ReadWriteCloser, error) {
			return &previewTestOrigin{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close(context.Background())

	now := time.Now().UTC()
	leaseA, attachmentA := providerTestLeaseAttachment(t, now, "preview_a", "operation_a_01", "route_a_01", identity, 1)
	leaseB, attachmentB := providerTestLeaseAttachment(t, now, "preview_b", "operation_b_01", "route_b_01", identity, 1)
	carrierA, err := provider.CarrierForAttachment(ctx, leaseA, attachmentA)
	if err != nil {
		t.Fatal(err)
	}
	carrierB, err := provider.CarrierForAttachment(ctx, leaseB, attachmentB)
	if err != nil {
		t.Fatal(err)
	}
	first := carrierA.(*attachmentPreviewCarrier).inner
	second := carrierB.(*attachmentPreviewCarrier).inner
	if first.hub != second.hub {
		t.Fatal("two routes on one active carrier created separate accept hubs")
	}
	if first.routeID != "route_a_01" || second.routeID != "route_b_01" {
		t.Fatalf("route registrations = %q, %q", first.routeID, second.routeID)
	}
	if source.calls() != 2 {
		t.Fatalf("session source calls = %d, want one acquisition per attachment", source.calls())
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := carrierA.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CarrierForAttachment(ctx, leaseB, attachmentB); err != nil {
		t.Fatalf("remaining route should reuse live hub after one route closes: %v", err)
	}
	if source.releases() != 2 {
		t.Fatalf("released source references = %d, want two balanced route acquisitions while stable hub remains", source.releases())
	}
	if err := carrierB.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if source.releases() != 2 {
		t.Fatalf("released source references after final route close = %d, want two", source.releases())
	}
	if err := provider.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if source.releases() != 3 {
		t.Fatalf("released source references after provider close = %d, want three", source.releases())
	}
}

func TestAttachmentPreviewCarrierProviderFencesReplacementGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identityOne := testPreviewCarrierIdentity(1)
	pairOne := newPreviewCarrierPair(t, ctx, identityOne)
	defer pairOne.close()
	identityTwo := identityOne
	identityTwo.SessionID = "session_02"
	identityTwo.Generation = 2
	pairTwo := newPreviewCarrierPair(t, ctx, identityTwo)
	defer pairTwo.close()
	source := newProviderSessionSource(AttachmentSession{Active: pairOne.active, Identity: identityOne})
	provider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{Sessions: source, RunContext: ctx})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close(context.Background())

	now := time.Now().UTC()
	leaseOne, attachmentOne := providerTestLeaseAttachment(t, now, "preview_replace", "operation_replace_01", "route_replace_01", identityOne, 1)
	oldCarrier, err := provider.CarrierForAttachment(ctx, leaseOne, attachmentOne)
	if err != nil {
		t.Fatal(err)
	}
	oldHub := oldCarrier.(*attachmentPreviewCarrier).inner.hub

	source.mu.Lock()
	source.value = AttachmentSession{Active: pairTwo.active, Identity: identityTwo, Release: source.release}
	source.mu.Unlock()
	leaseTwo, attachmentTwo := providerTestLeaseAttachment(t, now, "preview_replace", "operation_replace_01", "route_replace_02", identityTwo, 1)
	newCarrier, err := provider.CarrierForAttachment(ctx, leaseTwo, attachmentTwo)
	if err != nil {
		t.Fatal(err)
	}
	newHub := newCarrier.(*attachmentPreviewCarrier).inner.hub
	if newHub == oldHub {
		t.Fatal("replacement identity reused old hub")
	}
	select {
	case <-oldHub.Done():
	case <-time.After(time.Second):
		t.Fatal("old hub was not fenced after carrier replacement")
	}
	if oldHub.Identity() != identityOne || newHub.Identity() != identityTwo {
		t.Fatalf("hub identities = old=%+v new=%+v", oldHub.Identity(), newHub.Identity())
	}
}

func TestAttachmentPreviewCarrierProviderRejectsUnsafeOrMismatchedAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	provider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{
		Sessions: providerSessionSourceFunc(func(context.Context, CarrierAdmission) (AttachmentSession, error) {
			return AttachmentSession{Active: pair.active, Identity: identity, Release: func(context.Context) error { return nil }}, nil
		}), RunContext: ctx,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close(context.Background())
	now := time.Now().UTC()
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_invalid", "operation_invalid_01", "route_invalid_01", identity, 1)
	attachment.State = "pending"
	attachment.EdgeReady = false
	if _, err := provider.CarrierForAttachment(ctx, lease, attachment); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("pending attachment error = %v, want binding error", err)
	}
	_, attachment = providerTestLeaseAttachment(t, now, "preview_invalid", "operation_invalid_01", "route_invalid_01", identity, 1)
	attachment.OperationID = "operation_other_01"
	attachment.IdempotencyKey = attachment.OperationID
	attachment.Binding.OperationID = attachment.OperationID
	if _, err := provider.CarrierForAttachment(ctx, lease, attachment); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("mismatched attachment error = %v, want binding error", err)
	}

	source := AttachmentSessionSourceFunc(func(context.Context, CarrierAdmission) (AttachmentSession, error) {
		wrong := identity
		wrong.SessionID = "other_session"
		return AttachmentSession{Active: pair.active, Identity: wrong}, nil
	})
	wrongProvider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{Sessions: source, RunContext: ctx})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongProvider.Close(context.Background())
	_, attachment = providerTestLeaseAttachment(t, now, "preview_invalid", "operation_invalid_01", "route_invalid_01", identity, 1)
	if _, err := wrongProvider.CarrierForAttachment(ctx, lease, attachment); !errors.Is(err, ErrAttachmentSessionInvalid) {
		t.Fatalf("wrong source identity error = %v, want session error", err)
	}
}

type providerSessionSource struct {
	mu       sync.Mutex
	value    AttachmentSession
	count    int
	released int
}

func newProviderSessionSource(value AttachmentSession) *providerSessionSource {
	source := &providerSessionSource{value: value}
	source.value.Release = source.release
	return source
}

func (s *providerSessionSource) AcquirePreviewDataCarrier(_ context.Context, _ CarrierAdmission) (AttachmentSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return s.value, nil
}

func (s *providerSessionSource) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *providerSessionSource) release(context.Context) error {
	s.mu.Lock()
	s.released++
	s.mu.Unlock()
	return nil
}

func (s *providerSessionSource) releases() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.released
}

type providerSessionSourceFunc func(context.Context, CarrierAdmission) (AttachmentSession, error)

func (f providerSessionSourceFunc) AcquirePreviewDataCarrier(ctx context.Context, admission CarrierAdmission) (AttachmentSession, error) {
	return f(ctx, admission)
}

func providerTestLeaseAttachment(t *testing.T, now time.Time, previewID, operationID, routeID string, identity connector.DataCarrierIdentity, leaseGeneration uint64) (Lease, Attachment) {
	t.Helper()
	request := AttachmentRequest{PreviewID: previewID, OperationID: operationID, OwnerDeviceID: identity.HostID, OwnerSessionID: "owner_session_01", IdempotencyKey: operationID, RequestID: "request_" + previewID, CorrelationID: "correlation_" + previewID}
	accountID := identity.AccountID
	hash, err := request.Hash(accountID)
	if err != nil {
		t.Fatal(err)
	}
	machinePublicKey := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	configHash := sha256.Sum256([]byte("config:" + strconv.FormatUint(identity.Generation, 10)))
	lease := Lease{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewLeaseKind, ID: previewID, AccountID: accountID, ActorID: "actor_01",
		OwnerDeviceID: identity.HostID, OwnerSessionID: request.OwnerSessionID, Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"},
		AccessMode: "public", Endpoint: "https://preview.example.test", LeaseDeadline: now.Add(time.Hour),
		State: "connecting", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: now.Add(-time.Minute), LastRenewedAt: now,
		CreateOperationID: operationID, Generation: int64(leaseGeneration), ETag: formatLeaseETag(previewID, int64(leaseGeneration)),
	}
	attachment := Attachment{
		Schema: PreviewTunnelSchemaV1, Kind: PreviewCarrierAttachmentKind,
		Binding:        Binding{AccountID: accountID, PreviewID: previewID, OperationID: operationID, OwnerDeviceID: identity.HostID, OwnerSessionID: request.OwnerSessionID, HostID: identity.HostID, LeaseGeneration: leaseGeneration, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, ConfigGeneration: identity.Generation, RouteID: routeID, RouteGeneration: 1, EdgeNodeID: "edge_node_01", EdgeProcessEpoch: "edge_epoch_01", MachineIdentityPublicKey: machinePublicKey, MachineIdentityThumbprint: machineIdentityThumbprint(machinePublicKey)},
		IdempotencyKey: operationID, RequestID: request.RequestID, CorrelationID: request.CorrelationID, RequestHash: hash,
		Endpoint: lease.Endpoint, Target: lease.Target, AccessMode: lease.AccessMode, ConfigContentHash: "sha256:" + hex.EncodeToString(configHash[:]), EdgeEndpoints: []string{"tls://edge.example.test"}, AttachmentGeneration: 1,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute), State: "edge_ready", EdgeReady: true,
	}
	_, edgeCertificate := testEdgeServerCertificate(t, now, identity, attachment.Binding.EdgeProcessEpoch)
	attachment.Binding.EdgeCarrierServerSPKISHA256, attachment.Binding.EdgeCarrierServerCertificateChainPEM = testEdgeServerTrust(t, edgeCertificate)
	if err := attachment.Validate(now); err != nil {
		t.Fatal(err)
	}
	return lease, attachment
}

var _ AttachmentSessionSource = (*providerSessionSource)(nil)
var _ AttachmentSessionSource = providerSessionSourceFunc(nil)

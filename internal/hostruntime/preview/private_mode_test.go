package preview

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestAttachmentPreviewCarrierProviderPublishesPrivateAdmissionForEdgeAuthorization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	identity := testPreviewCarrierIdentity(1)
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_private", "operation_private_01", "route_private_01", identity, 1)
	lease.AccessMode = "private"
	attachment.AccessMode = "private"
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()
	source := newProviderSessionSource(AttachmentSession{Active: pair.active, Identity: identity})
	privateAccess, err := newPrivateAccessSource(&privateAccessGrantClient{})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewAttachmentPreviewCarrierProvider(AttachmentPreviewCarrierProviderConfig{
		Sessions: source, PrivateAccess: privateAccess, RunContext: ctx,
		OriginDial: func(context.Context, LeaseTarget) (io.ReadWriteCloser, error) { return &previewTestOrigin{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := provider.CarrierForAttachment(ctx, lease, attachment)
	if err != nil {
		t.Fatalf("private carrier error = %v", err)
	}
	if carrier == nil {
		t.Fatal("private admission did not publish a carrier")
	}
	routes, err := privateAccess.Snapshot(ctx)
	if err != nil || len(routes) != 1 || routes[0].Hostname != "preview.example.test" {
		t.Fatalf("private routes = %+v, err=%v", routes, err)
	}
	if err := carrier.Close(ctx); err != nil {
		t.Fatal(err)
	}
	routes, err = privateAccess.Snapshot(ctx)
	if err != nil || len(routes) != 0 {
		t.Fatalf("private routes after close = %+v, err=%v", routes, err)
	}
	if err := provider.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

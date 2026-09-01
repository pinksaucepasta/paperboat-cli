package serve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
)

type foregroundSession struct {
	ready      preview.Lease
	readyDone  chan struct{}
	stopDone   chan struct{}
	stopOnce   sync.Once
	waitResult error
}

type composedLeaseClient struct {
	lease  preview.Lease
	create preview.LeaseRequest
}

func (c *composedLeaseClient) Create(_ context.Context, request preview.LeaseRequest) (preview.Lease, error) {
	c.create = request
	lease := c.lease
	lease.Target = request.Target
	lease.OwnerDeviceID = request.OwnerDeviceID
	lease.OwnerSessionID = request.OwnerSessionID
	return lease, nil
}

func (c *composedLeaseClient) Renew(_ context.Context, lease preview.Lease, _ string) (preview.Lease, error) {
	return lease, nil
}

func (c *composedLeaseClient) Stop(context.Context, preview.Lease, string) error { return nil }

type composedCarrier struct{}

func (composedCarrier) Run(ctx context.Context, lease preview.Lease, ready func(preview.Lease) error) error {
	if err := ready(lease); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func (composedCarrier) Close(context.Context) error { return nil }

func TestForegroundRejectsNilSessionStarterResult(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := ResolveSource(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = StartForeground(context.Background(), ForegroundConfig{
		Source: source, Name: "docs", Session: func(context.Context, uint16) (PreviewSession, error) {
			return nil, nil
		}, DrainTimeout: time.Second,
	})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("nil session result error = %v", err)
	}
}

func (s *foregroundSession) WaitReady(context.Context) (preview.Lease, error) {
	<-s.readyDone
	return s.ready, nil
}

func (s *foregroundSession) Wait() error {
	<-s.stopDone
	return s.waitResult
}

func (s *foregroundSession) Stop(context.Context) error {
	s.stopOnce.Do(func() { close(s.stopDone) })
	return nil
}

func TestForegroundUsesSessionReadyBoundaryAndStopsLease(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := ResolveSource(file)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := &foregroundSession{
		ready: preview.Lease{
			Schema: preview.PreviewTunnelSchemaV1, Kind: preview.PreviewLeaseKind, ID: "prv_1", AccountID: "acct_1",
			OwnerDeviceID: "device_1", OwnerSessionID: "session_1", AccessMode: "public", Endpoint: "https://quiet.preview.test",
			LeaseDeadline: now.Add(time.Hour), State: "ready", AllocationState: "ready", EdgeState: "ready", OriginState: "ready",
			ETag: `"preview:1"`, Target: preview.LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, CreatedAt: now,
		},
		readyDone: make(chan struct{}), stopDone: make(chan struct{}),
	}
	close(session.readyDone)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calledPort := make(chan uint16, 1)
	startedContext := make(chan context.Context, 1)
	foreground, err := StartForeground(ctx, ForegroundConfig{
		Source: source, Name: "docs", Session: func(sessionCtx context.Context, port uint16) (PreviewSession, error) {
			calledPort <- port
			startedContext <- sessionCtx
			return session, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if port := <-calledPort; port == 0 {
		t.Fatal("session starter received no origin port")
	}
	if foreground.Lease.Endpoint != session.ready.Endpoint || foreground.Lease.State != "ready" || foreground.Lease.ID != "prv_1" {
		t.Fatalf("foreground lease = %#v", foreground.Lease)
	}
	cancel()
	if err := foreground.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.stopDone:
	default:
		t.Fatal("session was not stopped")
	}
	select {
	case <-((<-startedContext).Done()):
	case <-time.After(time.Second):
		t.Fatal("foreground preview context was not canceled")
	}
}

func TestForegroundComposesCanonicalSessionAfterActualListenerPort(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := ResolveSource(file)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	client := &composedLeaseClient{lease: preview.Lease{
		Schema: preview.PreviewTunnelSchemaV1, Kind: preview.PreviewLeaseKind, ID: "prv_1", AccountID: "acct_1", ActorID: "actor_1",
		AccessMode: "public", Endpoint: "https://quiet.preview.test", LeaseDeadline: now.Add(time.Hour), State: "ready",
		AllocationState: "ready", EdgeState: "ready", OriginState: "ready", CreatedAt: now, LastRenewedAt: now,
		ETag: `"ptv1:preview_lease:cHJ2XzE:1"`,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	foreground, err := StartForeground(ctx, ForegroundConfig{
		Source: source, Name: "docs", Indefinite: true, LeaseClient: client, Carrier: composedCarrier{},
		OwnerDeviceID: "device_1", OwnerSessionID: "session_1", ReadyTimeout: time.Second, DrainTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.create.Target.Scheme != "http" || client.create.Target.Address == "" {
		t.Fatalf("created target=%#v", client.create.Target)
	}
	if !strings.HasPrefix(client.create.Target.Address, "127.0.0.1:") {
		t.Fatalf("created target address=%q", client.create.Target.Address)
	}
	if foreground.Lease.Endpoint != client.lease.Endpoint || foreground.Lease.State != "ready" {
		t.Fatalf("foreground lease=%#v", foreground.Lease)
	}
	cancel()
	if err := foreground.Wait(); err != nil {
		t.Fatal(err)
	}
}

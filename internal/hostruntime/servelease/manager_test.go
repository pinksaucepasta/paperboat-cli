package servelease

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestManagerLeaseLifecycleAndFencing(t *testing.T) {
	now := time.Now().UTC()
	manager, err := New(Config{TTL: 15 * time.Second, Interval: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.Acquire("docs")
	if err != nil || lease.ID == "" {
		t.Fatalf("lease=%#v err=%v", lease, err)
	}
	if _, err := manager.Acquire("docs"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate acquire error=%v", err)
	}
	now = now.Add(5 * time.Second)
	renewed, err := manager.Renew(lease.ID, lease.Name)
	if err != nil || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("renewed=%#v err=%v", renewed, err)
	}
	if err := manager.Release("wrong", lease.Name); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong fencing token error=%v", err)
	}
	if err := manager.Release(lease.ID, lease.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Renew(lease.ID, lease.Name); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("renew after release error=%v", err)
	}
}

func TestManagerRecoversLeaseAcrossRuntimeRestart(t *testing.T) {
	var mu sync.Mutex
	now := time.Now().UTC()
	statePath := filepath.Join(t.TempDir(), "runtime", "serve-leases.json")
	nowFunc := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	first, err := New(Config{TTL: 3 * time.Second, Interval: time.Millisecond, Now: nowFunc, StatePath: statePath})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := first.Acquire("docs")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !secureStateFile(statePath, info) {
		t.Fatalf("lease state permissions=%v", info.Mode().Perm())
	}
	expired := make(chan Lease, 1)
	second, err := New(Config{TTL: 3 * time.Second, Interval: time.Millisecond, Now: nowFunc, StatePath: statePath, Expired: func(_ context.Context, got Lease) error {
		expired <- got
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Acquire("docs"); !errors.Is(err, ErrConflict) {
		t.Fatalf("recovered lease was not fenced: %v", err)
	}
	mu.Lock()
	now = now.Add(4 * time.Second)
	mu.Unlock()
	if err := second.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-expired:
		if got.ID != lease.ID {
			t.Fatalf("expired recovered lease=%#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("recovered lease did not reconcile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := second.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerExpiresAbandonedLease(t *testing.T) {
	var mu sync.Mutex
	now := time.Now().UTC()
	expired := make(chan Lease, 1)
	manager, err := New(Config{TTL: 3 * time.Second, Interval: time.Millisecond, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}, Expired: func(_ context.Context, lease Lease) error {
		expired <- lease
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	lease, _ := manager.Acquire("docs")
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(4 * time.Second)
	mu.Unlock()
	select {
	case got := <-expired:
		if got.ID != lease.ID {
			t.Fatalf("expired=%#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("abandoned lease was not expired")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClientNegotiatesAndAuthenticates(t *testing.T) {
	manager, _ := New(Config{TTL: 15 * time.Second, Interval: time.Second})
	server := httptest.NewServer(Handler{Manager: manager, Token: "local-secret"})
	defer server.Close()
	client, err := NewClient(server.URL+"/v1/serve-leases", "local-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Acquire(context.Background(), "docs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Renew(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := client.Release(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	unauthorized, _ := NewClient(server.URL+"/v1/serve-leases", "wrong", server.Client())
	if _, err := unauthorized.Acquire(context.Background(), "other"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unauthorized error=%v", err)
	}
}

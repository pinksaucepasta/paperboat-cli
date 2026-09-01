package preview

import (
	"context"
	"errors"
	"testing"
)

func TestSessionManagerTracksGenerationAndRekeysOnRenewal(t *testing.T) {
	session, _, _ := newSessionTest(t, func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	manager := NewSessionManager()
	if err := manager.Track(session); err != nil {
		t.Fatal(err)
	}
	oldKey := session.Key()
	if oldKey.Generation != 1 || manager.Count() != 1 {
		t.Fatalf("initial key=%#v count=%d", oldKey, manager.Count())
	}
	if _, err := manager.Get(oldKey); err != nil {
		t.Fatal(err)
	}
	renewed := session.currentLease()
	renewed.ETag = formatLeaseETag(renewed.ID, 2)
	if err := session.acceptRenewal(renewed, session.currentLease()); err != nil {
		t.Fatal(err)
	}
	newKey := session.Key()
	if newKey.Generation != 2 || newKey.LeaseID != oldKey.LeaseID || newKey.OwnerSessionID != oldKey.OwnerSessionID {
		t.Fatalf("renewed key=%#v old=%#v", newKey, oldKey)
	}
	if _, err := manager.Get(oldKey); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("old key error=%v", err)
	}
	if _, err := manager.Get(newKey); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke(context.Background(), newKey); err != nil {
		t.Fatal(err)
	}
	if manager.Count() != 0 {
		t.Fatalf("count after revoke=%d", manager.Count())
	}
}

func TestSessionManagerRejectsDuplicateAndDoesNotRestore(t *testing.T) {
	session, _, _ := newSessionTest(t, func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	manager := NewSessionManager()
	if err := manager.Track(session); err != nil {
		t.Fatal(err)
	}
	if err := manager.Track(session); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.Count() != 0 {
		t.Fatalf("count after shutdown=%d", manager.Count())
	}
	if restored := NewSessionManager(); restored.Count() != 0 {
		t.Fatalf("new manager restored %d sessions", restored.Count())
	}
	if err := manager.Track(session); !errors.Is(err, ErrSessionManagerStopped) {
		t.Fatalf("track after shutdown error=%v", err)
	}
}

func TestSessionManagerFencesSameLeaseOwnerAcrossGenerations(t *testing.T) {
	session, _, _ := newSessionTest(t, func(ctx context.Context, lease Lease, ready func(Lease) error) error {
		if err := ready(sessionReadyLease(lease)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	manager := NewSessionManager()
	if err := manager.Track(session); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.lease.Generation = 2
	session.lease.ETag = formatLeaseETag(session.lease.ID, 2)
	session.mu.Unlock()
	if err := manager.Track(session); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("same lease owner with a new generation error = %v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

package connector

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestDataCarrierSessionSourceTracksAuthoritativeIdentity(t *testing.T) {
	initial := testDataCarrierIdentity()
	advanced := initial
	advanced.SessionID = "session-b"
	advanced.ProcessGeneration = initial.ProcessGeneration + 1
	advanced.Generation = initial.Generation + 1
	stale := initial
	newer := advanced
	newer.SessionID = "session-c"
	newer.ProcessGeneration++
	newer.Generation++
	identities := []DataCarrierIdentity{advanced, stale, newer}
	var mu sync.Mutex
	sourceIndex := 0
	identitySource := func(context.Context) (DataCarrierIdentity, error) {
		mu.Lock()
		defer mu.Unlock()
		identity := identities[sourceIndex]
		sourceIndex++
		return identity, nil
	}
	config := DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = initial
	config.Carrier = testDataCarrierConfig()
	dialer := func(context.Context, DataCarrierDialRequest) (DataCarrierDialResult, error) {
		return DataCarrierDialResult{}, errors.New("dialer must not run")
	}
	sessionSource, err := NewDataCarrierSessionSource(initial, config, dialer)
	if err != nil {
		t.Fatalf("new session source: %v", err)
	}
	if sessionSource.Config.Session != (DataCarrierIdentity{}) {
		t.Fatalf("source retained mutable session template: %+v", sessionSource.Config.Session)
	}
	sessionSource.IdentitySource = identitySource

	request, err := sessionSource.PrepareDataCarrier(context.Background())
	if err != nil {
		t.Fatalf("prepare advanced identity: %v", err)
	}
	if request.Identity != advanced || request.Config.Session != advanced {
		t.Fatalf("advanced request identity/config = %+v/%+v, want %+v", request.Identity, request.Config.Session, advanced)
	}
	if _, err := sessionSource.PrepareDataCarrier(context.Background()); !errors.Is(err, ErrDataCarrierSessionSource) {
		t.Fatalf("stale identity error = %v, want session source error", err)
	}
	request, err = sessionSource.PrepareDataCarrier(context.Background())
	if err != nil {
		t.Fatalf("prepare newer identity: %v", err)
	}
	if request.Identity != newer {
		t.Fatalf("newer request identity = %+v, want %+v", request.Identity, newer)
	}
}

func TestDataCarrierSessionSourceRejectsHostRebinding(t *testing.T) {
	identity := testDataCarrierIdentity()
	config := DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"domain-a"}
	config.Session = identity
	config.Carrier = testDataCarrierConfig()
	sessionSource, err := NewDataCarrierSessionSource(identity, config, func(context.Context, DataCarrierDialRequest) (DataCarrierDialResult, error) {
		return DataCarrierDialResult{}, errors.New("dialer must not run")
	})
	if err != nil {
		t.Fatalf("new session source: %v", err)
	}
	rebound := identity
	rebound.HostID = "host-other"
	sessionSource.IdentitySource = func(context.Context) (DataCarrierIdentity, error) {
		return rebound, nil
	}
	if _, err := sessionSource.PrepareDataCarrier(context.Background()); !errors.Is(err, ErrDataCarrierSessionSource) {
		t.Fatalf("host rebinding error = %v, want session source error", err)
	}
}

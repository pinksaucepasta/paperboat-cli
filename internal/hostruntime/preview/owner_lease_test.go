package preview

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOwnerSessionLeaseManagerFencesReleaseAndAllowsBoundedReuse(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{
		MachineID: "machine_01", RuntimeDone: runtimeDone, MaxSessions: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewOwnerSessionLeaseManager(OwnerSessionLeaseManagerConfig{
		MachineID: "machine_01", ControlToken: "control_secret", Registry: registry,
		TTL: 10 * time.Second, MaxLeases: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	target := LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}
	first, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_01")
	if err != nil {
		t.Fatal(err)
	}
	if first.OwnerSessionID == "" || first.MachineID != "machine_01" || first.Target != target || !first.ExpiresAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("first lease = %+v", first)
	}
	replay, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_01")
	if err != nil || replay.ID != first.ID || replay.Token != first.Token {
		t.Fatalf("same-key replay = %+v, err=%v", replay, err)
	}
	if _, err := manager.Acquire(OwnerSessionLeaseRequest{Target: LeaseTarget{Scheme: "http", Address: "127.0.0.1:3001"}}, "owner_request_01"); !errors.Is(err, ErrOwnerSessionLeaseConflict) {
		t.Fatalf("same-key changed request error = %v", err)
	}
	if _, err := manager.Heartbeat(first.ID, "wrong_token"); !errors.Is(err, ErrOwnerSessionLeaseUnauthorized) {
		t.Fatalf("wrong heartbeat token error = %v", err)
	}
	now = now.Add(time.Second)
	updated, err := manager.Heartbeat(first.ID, first.Token)
	if err != nil || !updated.ExpiresAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("heartbeat = %+v, err=%v", updated, err)
	}
	if err := manager.Release(first.ID, "wrong_token"); !errors.Is(err, ErrOwnerSessionLeaseUnauthorized) {
		t.Fatalf("wrong release token error = %v", err)
	}
	if err := manager.Release(first.ID, first.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Heartbeat(first.ID, first.Token); !errors.Is(err, ErrOwnerSessionLeaseLost) {
		t.Fatalf("heartbeat after release error = %v", err)
	}
	if _, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_01"); !errors.Is(err, ErrOwnerSessionLeaseLost) {
		t.Fatalf("retired same-key replay error = %v", err)
	}
	// Release closes the owner lifetime immediately, while the manager keeps a
	// short retirement record to fence a delayed dispatch. A fresh idempotency
	// key can still use the bounded active-leases capacity.
	second, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_02")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.OwnerSessionID == first.OwnerSessionID {
		t.Fatalf("fresh lease reused identity: first=%+v second=%+v", first, second)
	}
	now = now.Add(20 * time.Second)
	manager.Sweep(now)
	third, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_01")
	if err != nil || third.ID == first.ID {
		t.Fatalf("retired request was not safely reusable: lease=%+v err=%v", third, err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerSessionLeaseManagerLocalAndDispatchReferencesAreIndependent(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{MachineID: "machine_01", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewOwnerSessionLeaseManager(OwnerSessionLeaseManagerConfig{MachineID: "machine_01", ControlToken: "control_secret", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	target := LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}
	lease, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_03")
	if err != nil {
		t.Fatal(err)
	}
	dispatchDone, err := registry.OwnerSessionDoneForTarget("account_01", "machine_01", lease.OwnerSessionID, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(lease.ID, lease.Token); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("local lease release did not close the owner lifetime")
	}
	if err := registry.ReleaseOwnerSession("account_01", "machine_01", lease.OwnerSessionID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("final dispatch reference did not close")
	}
	_ = manager.Close()
}

func TestOwnerSessionLeaseRetirementRejectsDelayedDispatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{MachineID: "machine_01", RuntimeDone: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewOwnerSessionLeaseManager(OwnerSessionLeaseManagerConfig{
		MachineID: "machine_01", ControlToken: "control_secret", Registry: registry,
		TTL: 10 * time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	target := LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}
	lease, err := manager.Acquire(OwnerSessionLeaseRequest{Target: target}, "owner_request_05")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(lease.ID, lease.Token); err != nil {
		t.Fatal(err)
	}
	now = now.Add(21 * time.Second)
	manager.Sweep(now)
	if _, err := registry.OwnerSessionDoneForTarget("account_01", "machine_01", lease.OwnerSessionID, target); !errors.Is(err, ErrOwnerSessionBinding) {
		t.Fatalf("retired local owner dispatch error = %v", err)
	}
}

func TestOwnerSessionLeaseHTTPClientRetriesSameKeyAndRejectsRedirects(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{MachineID: "machine_01", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewOwnerSessionLeaseManager(OwnerSessionLeaseManagerConfig{MachineID: "machine_01", ControlToken: "control_secret", Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(manager)
	defer server.Close()
	target := LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}
	var calls int
	var keys []string
	var mu sync.Mutex
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		call := calls
		mu.Unlock()
		if call == 1 {
			return nil, errors.New("uncertain connection close")
		}
		return http.DefaultTransport.RoundTrip(request)
	})
	client, err := NewLocalOwnerSessionClient(server.URL, "control_secret", &http.Client{Transport: transport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Acquire(context.Background(), "", target)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotCalls, gotKeys := calls, append([]string(nil), keys...)
	mu.Unlock()
	if gotCalls != 2 || len(gotKeys) != 2 || gotKeys[0] == "" || gotKeys[0] != gotKeys[1] {
		t.Fatalf("retry calls=%d keys=%v", gotCalls, gotKeys)
	}
	if err := client.Release(context.Background(), lease); err != nil {
		t.Fatal(err)
	}

	redirect := httptest.NewServer(http.RedirectHandler("http://127.0.0.1:1/secret", http.StatusFound))
	defer redirect.Close()
	redirectClient, err := NewLocalOwnerSessionClient(redirect.URL, "control_secret", &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirectClient.Acquire(context.Background(), "", target); !errors.Is(err, ErrOwnerSessionLeaseInvalid) {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestOwnerSessionLeaseClientRejectsDuplicateAndOversizedResponses(t *testing.T) {
	for _, responseBody := range []string{
		`{"schema":"paperboat.preview-owner-session/v1","schema":"paperboat.preview-owner-session/v1"}`,
		strings.Repeat("x", ownerSessionLeaseResponseLimit+1),
	} {
		client, err := NewLocalOwnerSessionClient("http://127.0.0.1:1", "control_secret", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(responseBody)), Header: make(http.Header)}, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.AcquireWithKey(context.Background(), "", LeaseTarget{Scheme: "http", Address: "127.0.0.1:3000"}, "owner_request_04"); !errors.Is(err, ErrOwnerSessionLeaseInvalid) {
			t.Fatalf("response %q error = %v", responseBody[:min(len(responseBody), 20)], err)
		}
	}
}

func TestLocalOwnerSessionEndpointRequiresLiteralLoopback(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:8080", "http://192.0.2.1:8080", "https://127.0.0.1:8080", "http://127.0.0.1:8080/path"} {
		if _, err := LocalOwnerSessionEndpoint(endpoint); !errors.Is(err, ErrOwnerSessionLeaseInvalid) {
			t.Fatalf("endpoint %q error = %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := LocalOwnerSessionEndpoint(endpoint); err != nil {
			t.Fatalf("endpoint %q error = %v", endpoint, err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

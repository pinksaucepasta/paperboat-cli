package preview

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRuntimeOwnerSessionRegistrySharesReferencesAndAllowsSafeReuse(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{
		AccountID: "account_01", MachineID: "machine_01", RuntimeDone: runtimeDone, MaxSessions: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same owner session did not share one runtime lifetime")
	}
	if err := registry.ReleaseOwnerSession("account_01", "machine_01", "owner_session_01"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
		t.Fatal("one concurrent preview release closed the shared owner lifetime")
	default:
	}
	if err := registry.ReleaseOwnerSession("account_01", "machine_01", "owner_session_01"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("final owner release did not close the lifetime")
	}
	reused, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatalf("released owner session should be reusable: %v", err)
	}
	if reused == first {
		t.Fatal("reused owner session returned the retired lifetime channel")
	}
	if err := registry.ReleaseOwnerSession("account_01", "machine_01", "owner_session_01"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOwnerSessionRegistryReusesCapacityAfterRelease(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{
		AccountID: "account_01", MachineID: "machine_01", RuntimeDone: runtimeDone, MaxSessions: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ownerSessionID := range []string{"owner_session_01", "owner_session_02", "owner_session_03"} {
		if _, err := registry.OwnerSessionDone("account_01", "machine_01", ownerSessionID); err != nil {
			t.Fatalf("register %s: %v", ownerSessionID, err)
		}
		if err := registry.ReleaseOwnerSession("account_01", "machine_01", ownerSessionID); err != nil {
			t.Fatalf("release %s: %v", ownerSessionID, err)
		}
	}
}

func TestRuntimeOwnerSessionRegistryBindsAccountMachineAndRuntime(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{AccountID: "account_01", MachineID: "machine_01", RuntimeDone: runtimeDone})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.OwnerSessionDone("account_02", "machine_01", "owner_session_01"); !errors.Is(err, ErrOwnerSessionBinding) {
		t.Fatalf("wrong account error = %v", err)
	}
	if _, err := registry.OwnerSessionDone("account_01", "machine_02", "owner_session_01"); !errors.Is(err, ErrOwnerSessionBinding) {
		t.Fatalf("wrong machine error = %v", err)
	}
	done, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	close(runtimeDone)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime shutdown did not close owner lifetime")
	}
	if _, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_02"); !errors.Is(err, ErrOwnerSessionRegistryClosed) {
		t.Fatalf("post-shutdown registration error = %v", err)
	}
	if err := registry.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOwnerSessionRegistryRequiresRuntimeLifetime(t *testing.T) {
	if _, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{AccountID: "account_01", MachineID: "machine_01"}); !errors.Is(err, ErrOwnerSessionRegistryInvalid) {
		t.Fatalf("nil runtime lifetime error = %v", err)
	}
	if _, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{AccountID: "account_01", MachineID: "machine_01", RuntimeDone: make(chan struct{}), MaxSessions: 0}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOwnerSessionRegistryMachineWideKeysIncludeAccount(t *testing.T) {
	runtimeDone := make(chan struct{})
	registry, err := NewRuntimeOwnerSessionRegistry(RuntimeOwnerSessionRegistryConfig{MachineID: "machine_01", RuntimeDone: runtimeDone, MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	first, err := registry.OwnerSessionDone("account_01", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.OwnerSessionDone("account_02", "machine_01", "owner_session_01")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("owner session reused lifetime across accounts")
	}
	if err := registry.ReleaseOwnerSession("account_01", "machine_01", "owner_session_01"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
	default:
		t.Fatal("released account lifetime did not close")
	}
	if err := registry.ReleaseOwnerSession("account_02", "machine_01", "owner_session_01"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second:
	default:
		t.Fatal("released second account lifetime did not close")
	}
}

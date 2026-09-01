//go:build darwin || linux

package runtime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
)

func TestPortableEnvironmentKeySourceUsesDefaultStateAndRetainsIdentity(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runtime")
	registration := runtimeidentity.Registration{MachineID: "mch_portable", InstallationGeneration: 7}
	firstSource, err := newPortableEnvironmentKeySource(stateRoot, registration)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstPrivate := first.Private
	first.Destroy()

	sealedPath := filepath.Join(stateRoot, environmentkey.PortableCredentialPath)
	if _, err := os.Stat(sealedPath); err != nil {
		t.Fatalf("default portable state was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, "environment-host-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected manually injected key path error=%v", err)
	}

	secondSource, err := newPortableEnvironmentKeySource(stateRoot, registration)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if firstPrivate != second.Private {
		t.Fatal("portable recipient changed across runtime restart")
	}
}

func TestPortableEnvironmentKeySourceRecreatedIdentityCannotOpenOldState(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runtime")
	registration := runtimeidentity.Registration{MachineID: "mch_portable", InstallationGeneration: 7}
	firstSource, err := newPortableEnvironmentKeySource(stateRoot, registration)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstPublic, err := first.Public()
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()

	identityPath := filepath.Join(stateRoot, "machine-identity.json")
	identityBytes, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identityBytes[len(identityBytes)-1] ^= 1
	if err := os.WriteFile(identityPath, identityBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// A replacement identity gets a new local root and must not silently open
	// or replace the existing sealed recipient.
	if _, err := newPortableEnvironmentKeySource(stateRoot, registration); !errors.Is(err, runtimeidentity.ErrInvalidStore) {
		t.Fatalf("recreated identity error=%v, want ErrInvalidStore", err)
	}

	newRoot := filepath.Join(t.TempDir(), "runtime")
	newSource, err := newPortableEnvironmentKeySource(newRoot, registration)
	if err != nil {
		t.Fatal(err)
	}
	newMaterial, err := newSource.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer newMaterial.Destroy()
	newPublic, err := newMaterial.Public()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstPublic[:], newPublic[:]) {
		t.Fatal("new identity/state reused old recipient")
	}
}

func TestProductionEnvironmentKeySourceSelectsPortableWithoutNativeBoundary(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("portable fallback selection is Linux-specific")
	}
	// A systemd credential alone cannot own the mutable monotonic genesis
	// marker, so headless service execution still uses the identity-wrapped
	// portable record.
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Join(t.TempDir(), "credentials"))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("PAPERBOAT_ENVIRONMENT_HOST_KEY_FILE", filepath.Join(t.TempDir(), "manual-key"))
	stateRoot := filepath.Join(t.TempDir(), "runtime")
	source, err := productionEnvironmentKeySourceForState(stateRoot, runtimeidentity.Registration{
		MachineID: "mch_portable", InstallationGeneration: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := source.(*environmentkey.PortableSource); !ok {
		t.Fatalf("source type=%T, want portable source", source)
	}
	material, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
}

func TestProductionEnvironmentKeySourceLiveIntegration(t *testing.T) {
	stateRoot := os.Getenv("PAPERBOAT_TEST_ENV_STATE_ROOT")
	machineID := os.Getenv("PAPERBOAT_TEST_ENV_MACHINE_ID")
	if stateRoot == "" || machineID == "" {
		t.Skip("live environment key source is not configured")
	}
	generation := uint64(1)
	source, err := productionEnvironmentKeySourceForState(stateRoot, runtimeidentity.Registration{
		MachineID: machineID, InstallationGeneration: int64(generation),
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
}

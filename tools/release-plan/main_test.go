package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/tools/releaseplan"
)

func TestReleasePlanCommandEndToEnd(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range releaseplan.ArtifactSpecs() {
		if err := os.WriteFile(filepath.Join(artifacts, artifact.Name), []byte("asset:"+artifact.Name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(root, "manifest.json")
	planPath := filepath.Join(root, "plan.json")
	targetPath := filepath.Join(root, "target.json")
	providerPath := filepath.Join(root, "provider.json")
	statePath := filepath.Join(root, "state.json")
	quarantinePath := filepath.Join(root, "quarantine.json")
	revocationPath := filepath.Join(root, "revocation.json")
	if err := run([]string{"manifest", "-version", "2026.08.31.1", "-source-commit", "0123456789abcdef0123456789abcdef01234567", "-toolchain", "go1.26.6", "-artifacts", artifacts, "-output", manifestPath}); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := run([]string{"plan", "-manifest", manifestPath, "-policy-revision", "7", "-severity", "security", "-cohort-seed", "release-seed", "-output", planPath}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	target := releaseplan.TargetBinding{MachineID: "machine-a", AccountID: "account-a", HostID: "host-a", TunnelID: "tunnel-a", ConnectorID: "connector-a", EdgeNodeID: "edge-a", FailureDomain: "iad-1", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5}
	targetBody, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseplan.WriteFile(targetPath, append(targetBody, '\n'), releaseplan.MaxProviderBytes); err != nil {
		t.Fatal(err)
	}
	manifest, err := releaseplan.LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := manifest.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"provider", "-plan", planPath, "-target", targetPath, "-transaction-id", "tx-a", "-previous-version", "2026.08.30.1", "-previous-manifest-sha256", manifestDigest, "-rollback-trigger", "edge_canary", "-output", providerPath}); err != nil {
		t.Fatalf("provider: %v", err)
	}
	if err := run([]string{"validate", "-manifest", manifestPath, "-plan", planPath, "-artifacts", artifacts, "-provider", providerPath}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := run([]string{"state-init", "-plan", planPath, "-transaction-id", "tx-a", "-previous-version", "2026.08.30.1", "-now", "2026-08-31T09:00:00Z", "-output", statePath}); err != nil {
		t.Fatalf("state-init: %v", err)
	}
	for _, event := range []string{"download_started", "candidate_validating", "candidate_ready", "canary_passed", "drain_completed", "activation_started", "activation_passed", "stability_passed"} {
		if err := run([]string{"advance", "-state", statePath, "-event", event, "-now", "2026-08-31T09:01:00Z"}); err != nil {
			t.Fatalf("advance %s: %v", event, err)
		}
	}
	state, err := releaseplan.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != releaseplan.StateCommitted {
		t.Fatalf("state=%s, want committed", state.State)
	}
	if err := run([]string{"state-init", "-plan", planPath, "-transaction-id", "tx-b", "-previous-version", "2026.08.30.1", "-now", "2026-08-31T09:00:00Z", "-output", statePath}); err != nil {
		t.Fatalf("state-init failure: %v", err)
	}
	for _, event := range []string{"download_started", "candidate_validating", "candidate_ready", "canary_failed"} {
		if err := run([]string{"advance", "-state", statePath, "-event", event, "-reason", "edge canary failed", "-now", "2026-08-31T09:01:00Z"}); err != nil {
			t.Fatalf("failure advance %s: %v", event, err)
		}
	}
	if err := run([]string{"quarantine", "-state", statePath, "-now", "2026-08-31T09:02:00Z", "-output", quarantinePath}); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if err := run([]string{"revoke", "-state", statePath, "-reason", "operator revoked", "-now", "2026-08-31T09:03:00Z", "-output", revocationPath}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := releaseplan.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked.Revoked || !revoked.Quarantined {
		t.Fatalf("revoked state=%+v", revoked)
	}
}

func TestReleasePlanCommandRejectsTamperingAndUnsafeArguments(t *testing.T) {
	if err := run([]string{"manifest", "-version", "2026.08.31.1", "-unknown", "x"}); err == nil {
		t.Fatal("unknown flag unexpectedly accepted")
	}
	path := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(path, []byte(`{"machine_id":"machine"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseplan.LoadTargetBinding(path); !errors.Is(err, releaseplan.ErrInvalidPlan) {
		t.Fatalf("invalid target error=%v", err)
	}
}

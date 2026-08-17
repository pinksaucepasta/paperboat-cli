package main

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
)

func testSSHTargetCacheMachine() api.UserMachine {
	return api.UserMachine{ID: "mch_1", Alias: "hn-byod-ready", DisplayName: "hn-byod-ready", InstallationGeneration: 4, EnvironmentID: "env_1", WorkspaceRoot: "/root"}
}

func TestSSHTargetCacheRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	machine := testSSHTargetCacheMachine()
	now := time.Unix(1_800_000_000, 0)
	target := api.ManagedSSHTarget{MachineID: machine.ID, MachineGeneration: 4, OSUser: "root", Port: 2222}
	if err := sshTargetCacheStore(cfg, machine, target, now); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, ok := sshTargetCacheLookup(cfg, machine, now.Add(2*time.Minute))
	if !ok || got.OSUser != "root" || got.Port != 2222 {
		t.Fatalf("lookup = %+v, %t", got, ok)
	}
}

func TestSSHTargetCacheExpiresAfterTTL(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	machine := testSSHTargetCacheMachine()
	now := time.Unix(1_800_000_000, 0)
	if err := sshTargetCacheStore(cfg, machine, api.ManagedSSHTarget{OSUser: "root", Port: 2222}, now); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := sshTargetCacheLookup(cfg, machine, now.Add(sshTargetCacheTTL+time.Second)); ok {
		t.Fatal("stale cache entry was accepted")
	}
}

func TestSSHTargetCacheRejectsGenerationChange(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	machine := testSSHTargetCacheMachine()
	now := time.Unix(1_800_000_000, 0)
	if err := sshTargetCacheStore(cfg, machine, api.ManagedSSHTarget{OSUser: "root", Port: 2222}, now); err != nil {
		t.Fatalf("store: %v", err)
	}
	reinstalled := machine
	reinstalled.InstallationGeneration = 5
	if _, ok := sshTargetCacheLookup(cfg, reinstalled, now.Add(time.Minute)); ok {
		t.Fatal("cache entry from a previous generation was accepted")
	}
}

func TestSSHTargetCacheRejectsDifferentServer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	machine := testSSHTargetCacheMachine()
	now := time.Unix(1_800_000_000, 0)
	if err := sshTargetCacheStore(cfg, machine, api.ManagedSSHTarget{OSUser: "root", Port: 2222}, now); err != nil {
		t.Fatalf("store: %v", err)
	}
	other := &config.Config{ServerURL: "https://other.paperboat.test"}
	if _, ok := sshTargetCacheLookup(other, machine, now.Add(time.Minute)); ok {
		t.Fatal("cache entry from another server was accepted")
	}
}

func TestSSHTargetCacheRejectsIncompleteEntry(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &config.Config{ServerURL: "https://api.paperboat.test"}
	machine := testSSHTargetCacheMachine()
	if err := sshTargetCacheStore(cfg, machine, api.ManagedSSHTarget{OSUser: "root"}, time.Now()); err == nil {
		t.Fatal("entry without a port was accepted")
	}
	if err := sshTargetCacheStore(cfg, machine, api.ManagedSSHTarget{Port: 22}, time.Now()); err == nil {
		t.Fatal("entry without an OS user was accepted")
	}
}

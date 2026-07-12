package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPreservesExplicitZeroDialRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"connect":{"dial_retries":0},"server_url":"https://api.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Connect.DialRetries != 0 {
		t.Fatalf("dial retries = %d, want explicit zero", cfg.Connect.DialRetries)
	}
}

func TestLoadAppliesDialRetryDefaultWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server_url":"https://api.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Connect.DialRetries != DefaultDialRetries {
		t.Fatalf("dial retries = %d, want %d", cfg.Connect.DialRetries, DefaultDialRetries)
	}
}

func TestSavePreservesExplicitZeroDialRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{path: path, dialRetriesConfigured: true}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Connect.DialRetries != 0 {
		t.Fatalf("dial retries = %d after save, want explicit zero", reloaded.Connect.DialRetries)
	}
}

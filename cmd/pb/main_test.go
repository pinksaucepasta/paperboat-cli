package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectWithServerURLFailsBeforeBrokerUntilWebSocketTransportExists(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	configPath := filepath.Join(dir, "config.json")

	if err := os.WriteFile(authPath, []byte(`{"access_token":"token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"papercode_config_path":`+quote(authPath)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err := newApp().Run([]string{"pb", "--config", configPath, "--server", "https://api.paperboat.test", "demo"})
	if err == nil {
		t.Fatal("expected backend attach guard error")
	}
	if !strings.Contains(err.Error(), "papercode WebSocket transport is required") {
		t.Fatalf("err = %v", err)
	}
}

func quote(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}

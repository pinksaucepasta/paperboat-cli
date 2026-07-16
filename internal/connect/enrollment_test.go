package connect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pujan-modha/paperboat-cli/internal/config"
)

func TestEnrollmentStoreSeparatesSecretFromMetadata(t *testing.T) {
	dir := t.TempDir()
	store := EnrollmentStore{Dir: filepath.Join(dir, "connector"), Secrets: config.FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	want := Enrollment{MachineID: "cm_1", EnvironmentID: "env_1", AgentunnelClientID: "cli_1", AgentunnelRouteID: "tun_1", AgentunnelServerURL: "https://agentunnel.example", PapercodeLocalURL: "http://127.0.0.1:4099", PapercodeBootstrap: PapercodeBootstrap{RelayURL: "https://paperboat.example", RelayIssuer: "https://paperboat.example", CloudUserID: "usr_1", EnvironmentCredential: "credential", CloudMintPublicKey: "public-key"}, Agentunnel: "secret-token", Version: "1.2.3"}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(store.Dir, "enrollment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(metadata) == "" || string(metadata) == "secret-token\n" || contains(string(metadata), "secret-token") {
		t.Fatalf("metadata leaked enrollment secret: %s", metadata)
	}
	info, err := os.Stat(filepath.Join(store.Dir, "enrollment.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("metadata mode = %v, err = %v", info.Mode().Perm(), err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("enrollment = %#v", got)
	}
}

func TestWriteAgentunnelMachineConfigSeparatesToken(t *testing.T) {
	dir := t.TempDir()
	configPath, err := WriteAgentunnelMachineConfig(dir, Enrollment{MachineID: "cm_1", AgentunnelRouteID: "tun_1", AgentunnelServerURL: "https://agentunnel.example", PapercodeLocalURL: "http://127.0.0.1:4099", PapercodeBootstrap: PapercodeBootstrap{RelayURL: "https://paperboat.example", RelayIssuer: "https://paperboat.example", CloudUserID: "usr_1", EnvironmentCredential: "credential", CloudMintPublicKey: "public-key"}, Agentunnel: "secret-token"})
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(config), "secret-token") || !contains(string(config), `"tunnel_id":"tun_1"`) || !contains(string(config), `"local_url":"http://127.0.0.1:4099"`) {
		t.Fatalf("unexpected config: %s", config)
	}
	token, err := os.ReadFile(filepath.Join(dir, "agentunnel-client.token"))
	if err != nil || string(token) != "secret-token\n" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	info, err := os.Stat(filepath.Join(dir, "agentunnel-client.token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %v, err = %v", info.Mode().Perm(), err)
	}
}

func contains(value, needle string) bool {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

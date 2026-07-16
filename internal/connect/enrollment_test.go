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
	if err := store.Save(Enrollment{MachineID: "cm_1", EnvironmentID: "env_1", Agentunnel: "secret-token", Version: "1.2.3"}); err != nil {
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
	if got.MachineID != "cm_1" || got.EnvironmentID != "env_1" || got.Agentunnel != "secret-token" || got.Version != "1.2.3" {
		t.Fatalf("enrollment = %#v", got)
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

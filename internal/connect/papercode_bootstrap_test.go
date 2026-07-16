package connect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPreparePapercodeStatePinsEnvironmentIdentity(t *testing.T) {
	dir := t.TempDir()
	baseDir, err := PreparePapercodeState(dir, Enrollment{EnvironmentID: "env_connected_machine"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "papercode-state"); baseDir != want {
		t.Fatalf("base dir = %q, want %q", baseDir, want)
	}
	contents, err := os.ReadFile(filepath.Join(baseDir, "userdata", "environment-id"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "env_connected_machine\n"; got != want {
		t.Fatalf("environment id = %q, want %q", got, want)
	}
}

func TestPapercodeBootstrapCommandsUseServerBaseDir(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "papercode-state")
	if got, want := papercodeSessionIssueArgs(baseDir), []string{"auth", "session", "issue", "--base-dir", baseDir, "--ttl", "2m", "--label", "paperboat-connect-bootstrap", "--json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("issue args = %#v, want %#v", got, want)
	}
	if got, want := papercodeSessionRevokeArgs(baseDir, "session-1"), []string{"auth", "session", "revoke", "--base-dir", baseDir, "session-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("revoke args = %#v, want %#v", got, want)
	}
}

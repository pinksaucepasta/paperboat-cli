//go:build darwin || linux

package managedssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSSHConfigInstallRepairAndExactUninstall(t *testing.T) {
	home := openSSHTestHome(t)
	directory := filepath.Join(home, ".ssh")
	original := []byte("# personal header\n\nHost *\n    ServerAliveInterval 30\n")
	if err := os.WriteFile(filepath.Join(directory, "config"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	config := openSSHTestConfig(home, "pprbt")
	installed, err := InstallOpenSSHConfig(config)
	if err != nil || !installed.Changed {
		t.Fatalf("installed=%+v error=%v", installed, err)
	}
	if err := ValidateOpenSSHConfig(config); err != nil {
		t.Fatalf("validate installed config: %v", err)
	}
	if err := ValidateInstalledOpenSSHConfig(home, uint32(os.Getuid()), config.AliasSuffix, config.AgentSocket); err != nil {
		t.Fatalf("validate daemon-installed config: %v", err)
	}
	alternate := config
	alternate.ProxyCommand = `"/opt/paperboat/pb" __ssh-proxy --host %h --port %p`
	alternate.KnownHostsCommand = `"/opt/paperboat/pb" __ssh-known-hosts --host %h --port %p`
	if err := ValidateOpenSSHConfig(alternate); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("path-specific validation error=%v", err)
	}
	if err := ValidateInstalledOpenSSHConfig(home, uint32(os.Getuid()), config.AliasSuffix, config.AgentSocket); err != nil {
		t.Fatalf("path-independent validation error=%v", err)
	}
	main := readOpenSSHTestFile(t, filepath.Join(directory, "config"))
	includeOffset := strings.Index(string(main), openSSHIncludeMarker)
	hostOffset := strings.Index(string(main), "Host *")
	if includeOffset < 0 || hostOffset < 0 || includeOffset > hostOffset || strings.Count(string(main), openSSHIncludeMarker) != 1 {
		t.Fatalf("main config=%q", main)
	}
	owned := string(readOpenSSHTestFile(t, filepath.Join(directory, "paperboat_config")))
	for _, required := range []string{"Host *.pprbt", "ProxyCommand " + config.ProxyCommand, "KnownHostsCommand " + config.KnownHostsCommand, "IdentityAgent \"" + config.AgentSocket + "\"", "IdentityFile \"" + config.IdentityFile + "\"", "IdentitiesOnly yes", "BatchMode yes", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "StrictHostKeyChecking yes", "CheckHostIP no", "UserKnownHostsFile none", "GlobalKnownHostsFile none"} {
		if !strings.Contains(owned, required) {
			t.Fatalf("owned config missing %q: %q", required, owned)
		}
	}
	replay, err := InstallOpenSSHConfig(config)
	if err != nil || replay.Changed {
		t.Fatalf("replay=%+v error=%v", replay, err)
	}
	updated := config
	updated.AliasSuffix = "new.pprbt"
	if err := ValidateOpenSSHConfig(updated); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("mismatched config validation error=%v", err)
	}
	repaired, err := InstallOpenSSHConfig(updated)
	if err != nil || !repaired.Changed {
		t.Fatalf("repaired=%+v error=%v", repaired, err)
	}
	mainAfterRepair := readOpenSSHTestFile(t, filepath.Join(directory, "config"))
	if string(mainAfterRepair) != string(main) || strings.Contains(string(readOpenSSHTestFile(t, filepath.Join(directory, "paperboat_config"))), "Host *.pprbt\n") {
		t.Fatal("suffix repair changed include or retained the old suffix")
	}
	uninstalled, err := UninstallOpenSSHConfig(home, uint32(os.Getuid()))
	if err != nil || !uninstalled.Changed {
		t.Fatalf("uninstalled=%+v error=%v", uninstalled, err)
	}
	if final := readOpenSSHTestFile(t, filepath.Join(directory, "config")); string(final) != string(original) {
		t.Fatalf("final config=%q want=%q", final, original)
	}
	for _, name := range []string{"paperboat_config", ".paperboat-config-install-v1.json", ".paperboat-config-transaction-v1.json"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatalf("%s remains after uninstall: %v", name, err)
		}
	}
	second, err := UninstallOpenSSHConfig(home, uint32(os.Getuid()))
	if err != nil || second.Changed {
		t.Fatalf("second uninstall=%+v error=%v", second, err)
	}
}

func TestOpenSSHConfigRendersCanonicalAndDisplayAliasUserPort(t *testing.T) {
	home := openSSHTestHome(t)
	config := openSSHTestConfig(home, "pprbt")
	config.Targets = []OpenSSHAliasTarget{{Alias: "victus-windows-e2e-fresh", DisplayName: "Victus-Windows-E2E-Fresh", User: "Pujan", Port: 38222}}
	if _, err := InstallOpenSSHConfig(config); err != nil {
		t.Fatal(err)
	}
	owned := string(readOpenSSHTestFile(t, filepath.Join(home, ".ssh", "paperboat_config")))
	want := "Host victus-windows-e2e-fresh.pprbt Victus-Windows-E2E-Fresh.pprbt\n    User Pujan\n    Port 38222\n"
	if !strings.Contains(owned, want) {
		t.Fatalf("owned config missing authoritative target: %q", owned)
	}
	if err := ValidateOpenSSHConfig(config); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSSHConfigRemovesCreatedMainConfigOnUninstall(t *testing.T) {
	home := openSSHTestHome(t)
	if _, err := InstallOpenSSHConfig(openSSHTestConfig(home, "pprbt")); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallOpenSSHConfig(home, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".ssh", "config")); !os.IsNotExist(err) {
		t.Fatalf("created main config remains: %v", err)
	}
}

func TestOpenSSHConfigAtomicallyUpgradesLegacyManagedFragment(t *testing.T) {
	home := openSSHTestHome(t)
	config := openSSHTestConfig(home, "pprbt")
	if _, err := InstallOpenSSHConfig(config); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(home, ".ssh")
	legacy := []byte(openSSHBeginMarker + "\n" +
		"Host *.pprbt\n" +
		"    ProxyCommand " + config.ProxyCommand + "\n" +
		"    KnownHostsCommand " + config.KnownHostsCommand + "\n" +
		"    IdentityAgent \"" + config.AgentSocket + "\"\n" +
		"    IdentitiesOnly yes\n" +
		"    BatchMode yes\n" +
		"    PasswordAuthentication no\n" +
		"    KbdInteractiveAuthentication no\n" +
		"    StrictHostKeyChecking yes\n" +
		"    CheckHostIP no\n" +
		"    UserKnownHostsFile none\n" +
		"    GlobalKnownHostsFile none\n" + openSSHEndMarker + "\n")
	if !validLegacyOwnedOpenSSHContent(legacy, "pprbt") {
		t.Fatal("test legacy fragment is invalid")
	}
	var record openSSHInstallRecord
	recordPath := filepath.Join(directory, ".paperboat-config-install-v1.json")
	if err := json.Unmarshal(readOpenSSHTestFile(t, recordPath), &record); err != nil {
		t.Fatal(err)
	}
	record.OwnedHash = hashOpenSSHBytes(legacy)
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "paperboat_config"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, append(recordJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	upgraded, err := InstallOpenSSHConfig(config)
	if err != nil || !upgraded.Changed {
		t.Fatalf("upgrade=%+v error=%v", upgraded, err)
	}
	if err := ValidateOpenSSHConfig(config); err != nil {
		t.Fatalf("validate upgraded config: %v", err)
	}
	if validLegacyOwnedOpenSSHContent(readOpenSSHTestFile(t, filepath.Join(directory, "paperboat_config")), "pprbt") {
		t.Fatal("legacy fragment remains after upgrade")
	}
}

func TestGeneratedOpenSSHConfigIsAcceptedByInstalledClient(t *testing.T) {
	executable, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is not installed")
	}
	home := openSSHTestHome(t)
	if _, err := InstallOpenSSHConfig(openSSHTestConfig(home, "pprbt")); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-G", "-F", filepath.Join(home, ".ssh", "paperboat_config"), "probe.pprbt")
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("OpenSSH rejected generated config: %v: %s", err, stderr.String())
	}
	effective := strings.ToLower(stdout.String())
	for _, required := range []string{"identitiesonly yes", "batchmode yes", "passwordauthentication no", "kbdinteractiveauthentication no"} {
		if !strings.Contains(effective, required+"\n") {
			t.Fatalf("OpenSSH effective config missing %q:\n%s", required, stdout.String())
		}
	}
}

func TestOpenSSHConfigRejectsConflictsSymlinksAndModifiedOwnedState(t *testing.T) {
	home := openSSHTestHome(t)
	directory := filepath.Join(home, ".ssh")
	conflicting := "Host *.pprbt\n    ProxyCommand /tmp/other-proxy %h %p\n"
	if err := os.WriteFile(filepath.Join(directory, "config"), []byte(conflicting), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := InstallOpenSSHConfig(openSSHTestConfig(home, "pprbt"))
	var optionConflict *OpenSSHOptionConflict
	if !errors.As(err, &optionConflict) || optionConflict.Line != 2 || optionConflict.Option != "ProxyCommand" || optionConflict.Existing != "/tmp/other-proxy %h %p" {
		t.Fatalf("option conflict=%+v error=%v", optionConflict, err)
	}
	if err := os.Remove(filepath.Join(directory, "config")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "outside-config")
	if err := os.WriteFile(target, []byte("Host outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "config")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := InstallOpenSSHConfig(openSSHTestConfig(home, "pprbt")); err == nil {
		t.Fatal("symlinked main config was accepted")
	}
	if string(readOpenSSHTestFile(t, target)) != "Host outside\n" {
		t.Fatal("symlink target was modified")
	}
	if err := os.Remove(filepath.Join(directory, "config")); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallOpenSSHConfig(openSSHTestConfig(home, "pprbt")); err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(directory, "paperboat_config")
	if err := os.WriteFile(ownedPath, []byte("Host attacker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UninstallOpenSSHConfig(home, uint32(os.Getuid())); !errors.Is(err, ErrOpenSSHConfigConflict) {
		t.Fatalf("modified owned state error=%v", err)
	}
}

func TestOpenSSHConfigRecoversInterruptedTransaction(t *testing.T) {
	home := openSSHTestHome(t)
	directory := filepath.Join(home, ".ssh")
	config := openSSHTestConfig(home, "pprbt")
	if _, err := InstallOpenSSHConfig(config); err != nil {
		t.Fatal(err)
	}
	main := readOpenSSHTestFile(t, filepath.Join(directory, "config"))
	owned := readOpenSSHTestFile(t, filepath.Join(directory, "paperboat_config"))
	var record openSSHInstallRecord
	if err := json.Unmarshal(readOpenSSHTestFile(t, filepath.Join(directory, ".paperboat-config-install-v1.json")), &record); err != nil {
		t.Fatal(err)
	}
	transaction := openSSHTransaction{
		Version: 1, OriginalMain: encodeOpenSSHBytes(main), OriginalMainSet: true,
		OriginalOwned: encodeOpenSSHBytes(owned), OriginalOwnSet: true, OriginalRecord: &record,
		NextMain: encodeOpenSSHBytes(main), NextMainSet: true,
		NextOwned: encodeOpenSSHBytes([]byte("partial replacement\n")), NextOwnedSet: true,
	}
	journal, _ := json.Marshal(transaction)
	if err := os.WriteFile(filepath.Join(directory, ".paperboat-config-transaction-v1.json"), append(journal, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "paperboat_config"), []byte("partial replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := InstallOpenSSHConfig(config)
	if err != nil || recovered.Changed {
		t.Fatalf("recovered=%+v error=%v", recovered, err)
	}
	if value := readOpenSSHTestFile(t, filepath.Join(directory, "paperboat_config")); string(value) != string(owned) {
		t.Fatalf("recovered owned config=%q", value)
	}
	if _, err := os.Lstat(filepath.Join(directory, ".paperboat-config-transaction-v1.json")); !os.IsNotExist(err) {
		t.Fatalf("journal remains: %v", err)
	}
}

func openSSHTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func openSSHTestConfig(home, suffix string) OpenSSHConfig {
	return OpenSSHConfig{
		Home: home, OwnerUID: uint32(os.Getuid()), AliasSuffix: suffix,
		ProxyCommand:      "\"/usr/local/bin/pb\" internal ssh-proxy --host %h --port %p",
		KnownHostsCommand: "\"/usr/local/bin/pb\" internal ssh-known-hosts --host %h --port %p",
		AgentSocket:       filepath.Join(home, ".paperboat", "run", "ssh-agent.sock"),
		IdentityFile:      ManagedIdentityPublicKeyPath(home),
	}
}

func readOpenSSHTestFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

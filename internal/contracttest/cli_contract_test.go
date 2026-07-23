package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCommandTreeHasUniqueNamesAndAliases(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/cli/command-tree.json")
	if err != nil {
		t.Fatal(err)
	}
	var tree struct {
		Version  string `json:"version"`
		Commands []struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatal(err)
	}
	if tree.Version != "1.0.0" || len(tree.Commands) == 0 {
		t.Fatalf("invalid command tree: %#v", tree)
	}
	seen := map[string]string{}
	for _, command := range tree.Commands {
		for _, spelling := range append([]string{command.Name}, command.Aliases...) {
			if previous, exists := seen[spelling]; exists {
				t.Fatalf("command spelling %q is shared by %q and %q", spelling, previous, command.Name)
			}
			seen[spelling] = command.Name
		}
	}
	for _, required := range []string{"login", "create", "session list", "preview list", "preview revoke", "machine add", "config assign", "doctor"} {
		if _, ok := seen[required]; !ok {
			t.Errorf("missing required workflow spelling %q", required)
		}
	}
}

func TestExitCodeTaxonomy(t *testing.T) {
	b, err := os.ReadFile("../../testdata/contracts/cli/exit-codes.json")
	if err != nil {
		t.Fatal(err)
	}
	var taxonomy struct {
		Categories map[string]int `json:"categories"`
	}
	if err := json.Unmarshal(b, &taxonomy); err != nil {
		t.Fatal(err)
	}
	required := []string{"success", "usage", "authentication", "authorization_or_entitlement", "unavailable_retryable", "conflict", "canceled", "local_io", "protocol_incompatible"}
	seen := map[int]string{}
	for _, category := range required {
		code, ok := taxonomy.Categories[category]
		if !ok {
			t.Errorf("missing exit category %q", category)
			continue
		}
		if previous, duplicate := seen[code]; duplicate {
			t.Errorf("exit code %d shared by %s and %s", code, previous, category)
		}
		seen[code] = category
	}
}

func TestJSONOutputFixturesSeparateDataAndError(t *testing.T) {
	for _, name := range []string{"environment-list.success.json", "ambiguous-target.error.json"} {
		b, err := os.ReadFile("../../testdata/contracts/fixtures/cli/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			SchemaVersion string          `json:"schema_version"`
			OK            bool            `json:"ok"`
			Data          json.RawMessage `json:"data"`
			Error         json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(b, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.SchemaVersion != "1.0" || (envelope.Data != nil) == (envelope.Error != nil) || envelope.OK != (envelope.Data != nil) {
			t.Errorf("invalid output envelope %s", name)
		}
	}
}

func TestWorkflowTranscriptCoverage(t *testing.T) {
	required := map[string]bool{
		"first-use-no-server": false, "normal-default-attach": false,
		"safe-readiness-retry": false, "ambiguous-environment": false,
		"session-delete-nontty": false, "session-delete-confirm-decline": false,
		"revoked-session": false, "expired-refresh-recovers": false,
		"quota-failure": false, "replay-gap": false,
		"cancel-readiness-wait": false, "remote-exit-42": false,
		"protocol-incompatible": false,
	}
	f, err := os.Open("../../testdata/contracts/transcripts/cli/workflows.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var transcript struct {
			Case            string   `json:"case"`
			Argv            []string `json:"argv"`
			Stdout          string   `json:"stdout"`
			TerminalControl []string `json:"terminal_control"`
			RemoteExit      *int     `json:"remote_process_exit"`
			Exit            int      `json:"exit"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &transcript); err != nil {
			t.Fatal(err)
		}
		if _, ok := required[transcript.Case]; !ok || len(transcript.Argv) == 0 || transcript.Argv[0] != "pb" {
			t.Fatalf("invalid transcript identity: %#v", transcript)
		}
		if transcript.RemoteExit != nil && transcript.Exit != *transcript.RemoteExit {
			t.Errorf("%s does not propagate remote exit", transcript.Case)
		}
		enteredRaw := false
		for _, control := range transcript.TerminalControl {
			if control == "enter_raw" {
				enteredRaw = true
			}
			if control == "restore" {
				enteredRaw = false
			}
		}
		if enteredRaw {
			t.Errorf("%s leaves terminal raw", transcript.Case)
		}
		required[transcript.Case] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for name, seen := range required {
		if !seen {
			t.Errorf("missing workflow transcript %q", name)
		}
	}
}

func TestEveryCommandHasBehaviorAndTranscript(t *testing.T) {
	var tree struct {
		Commands []struct {
			Name string `json:"name"`
		} `json:"commands"`
	}
	readContractJSON(t, "cli/command-tree.json", &tree)
	want := map[string]bool{}
	for _, command := range tree.Commands {
		want[command.Name] = true
	}

	var behavior struct {
		Defaults map[string]any `json:"defaults"`
		Commands []struct {
			Name         string   `json:"name"`
			Mutation     string   `json:"mutation"`
			TTY          string   `json:"tty"`
			Confirmation string   `json:"confirmation"`
			Retry        string   `json:"retry"`
			Idempotency  string   `json:"idempotency"`
			Stdout       string   `json:"stdout"`
			Errors       []string `json:"errors"`
		} `json:"commands"`
	}
	readContractJSON(t, "cli/behavior.json", &behavior)
	if len(behavior.Defaults) == 0 {
		t.Fatal("CLI behavior defaults are required")
	}
	seenBehavior := map[string]bool{}
	for _, command := range behavior.Commands {
		if !want[command.Name] || seenBehavior[command.Name] {
			t.Fatalf("unknown or duplicate behavior for %q", command.Name)
		}
		if command.Mutation == "" || command.TTY == "" || command.Confirmation == "" || command.Retry == "" || command.Idempotency == "" || command.Stdout == "" || len(command.Errors) == 0 {
			t.Errorf("incomplete behavior for %q", command.Name)
		}
		seenBehavior[command.Name] = true
	}

	var transcripts struct {
		Inputs map[string]any `json:"inputs"`
		Cases  []struct {
			Command string   `json:"command"`
			Argv    []string `json:"argv"`
			Stdout  string   `json:"stdout"`
			Exit    int      `json:"exit"`
		} `json:"cases"`
	}
	readContractJSON(t, "transcripts/cli/commands.json", &transcripts)
	if len(transcripts.Inputs) == 0 {
		t.Fatal("deterministic transcript inputs are required")
	}
	seenTranscript := map[string]bool{}
	for _, transcript := range transcripts.Cases {
		if !want[transcript.Command] || seenTranscript[transcript.Command] || len(transcript.Argv) < 2 || transcript.Argv[0] != "pb" {
			t.Fatalf("invalid command transcript for %q", transcript.Command)
		}
		if slices.Contains(transcript.Argv, "--json") {
			var envelope struct {
				SchemaVersion string `json:"schema_version"`
			}
			if strings.Contains(transcript.Stdout, "\x1b") || json.Unmarshal([]byte(strings.TrimSpace(transcript.Stdout)), &envelope) != nil || envelope.SchemaVersion != "1.0" {
				t.Errorf("%s has invalid JSON stdout", transcript.Command)
			}
		}
		seenTranscript[transcript.Command] = true
	}
	for command := range want {
		if !seenBehavior[command] || !seenTranscript[command] {
			t.Errorf("command %q is not fully contracted", command)
		}
	}
}

func readContractJSON(t *testing.T, path string, target any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/contracts/" + path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, target); err != nil {
		t.Fatal(err)
	}
}

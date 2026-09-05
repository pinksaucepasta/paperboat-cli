package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNonTerminalOperationVectorCoverage(t *testing.T) {
	required := map[string]bool{
		"upload-valid": false, "upload-traversal": false, "upload-mime-mismatch": false,
		"config-stale-revision": false, "readiness-degraded": false,
	}
	f, err := os.Open("../../../testdata/contracts/fixtures/helper/operations.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var vector struct {
			Case      string          `json:"case"`
			Valid     bool            `json:"valid"`
			Operation string          `json:"operation"`
			Error     string          `json:"error"`
			Input     json.RawMessage `json:"input"`
			Result    json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		for _, token := range retiredPreviewTokens {
			if strings.Contains(string(scanner.Bytes()), token) {
				t.Fatalf("retired preview contract token %q in operation vector %q", token, vector.Case)
			}
		}
		if _, ok := required[vector.Case]; !ok {
			t.Fatalf("unknown operation vector %q", vector.Case)
		}
		if vector.Operation == "" {
			t.Errorf("%s: operation is required", vector.Case)
		}
		if !vector.Valid && vector.Error == "" {
			t.Errorf("%s: negative vector requires typed error", vector.Case)
		}
		if vector.Input == nil && vector.Result == nil {
			t.Errorf("%s: input or result is required", vector.Case)
		}
		required[vector.Case] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for name, seen := range required {
		if !seen {
			t.Errorf("missing operation vector %q", name)
		}
	}
}

func TestRetiredPreviewStateArtifactIsAbsent(t *testing.T) {
	statePath := "../../../testdata/contracts/states/preview.json"
	if _, err := os.Stat(statePath); err == nil {
		t.Fatalf("retired preview state artifact still exists: %s", statePath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat retired preview state artifact: %v", err)
	}

}

func TestPreviewCLIContractUsesCanonicalSurface(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/contracts/cli/command-tree.json")
	if err != nil {
		t.Fatal(err)
	}
	var tree struct {
		Commands []struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool, len(tree.Commands))
	for _, command := range tree.Commands {
		if legacyPreviewCommands[command.Name] {
			t.Fatalf("retired preview command %q remains in command tree", command.Name)
		}
		seen[command.Name] = true
		for _, alias := range command.Aliases {
			if legacyPreviewCommands[alias] {
				t.Fatalf("retired preview command alias %q remains in command tree", alias)
			}
		}
	}
	for _, command := range []string{"preview", "preview list", "preview stop"} {
		if !seen[command] {
			t.Errorf("canonical preview command %q is missing from command tree", command)
		}
	}
}

func TestPreviewCLIArtifactsDoNotExposeLegacyCommands(t *testing.T) {
	for _, artifact := range []struct {
		path  string
		field string
	}{
		{path: "../../../testdata/contracts/cli/behavior.json", field: "name"},
		{path: "../../../testdata/contracts/transcripts/cli/commands.json", field: "command"},
	} {
		b, err := os.ReadFile(artifact.path)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Commands []map[string]json.RawMessage `json:"commands"`
			Cases    []map[string]json.RawMessage `json:"cases"`
		}
		if err := json.Unmarshal(b, &document); err != nil {
			t.Fatalf("decode %s: %v", artifact.path, err)
		}
		records := document.Commands
		if artifact.field == "command" {
			records = document.Cases
		}
		for _, record := range records {
			var command string
			if raw := record[artifact.field]; raw != nil {
				if err := json.Unmarshal(raw, &command); err != nil {
					t.Fatalf("decode %s command: %v", artifact.path, err)
				}
			}
			if legacyPreviewCommands[command] {
				t.Fatalf("retired preview command %q remains in %s", command, artifact.path)
			}
		}
	}

	b, err := os.ReadFile("../../../testdata/contracts/credentials/classes.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range retiredPreviewTokens {
		if strings.Contains(string(b), token) {
			t.Fatalf("retired preview contract token %q remains in credential classes", token)
		}
	}
}

var retiredPreviewTokens = []string{
	"preview.public.v1",
	"preview.register",
	"preview_registration",
}

var legacyPreviewCommands = map[string]bool{
	"preview create":  true,
	"preview revoke":  true,
	"previews revoke": true,
	"previews":        true,
	"serve":           true,
}

package hoststate

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHostStateConsumesPreviewTunnelV1CredentialAndGenerationContracts(t *testing.T) {
	fixtures := filepath.Join("..", "..", "..", "testdata", "contracts", "preview-tunnel-v1", "fixtures", "resources.ndjson")
	file, err := os.Open(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	foundConnector, foundSnapshot := false, false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var vector struct {
			Valid    bool            `json:"valid"`
			Resource json.RawMessage `json:"resource"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if !vector.Valid {
			continue
		}
		var resource struct {
			Kind                string `json:"kind"`
			ID                  string `json:"id"`
			TunnelID            string `json:"tunnel_id"`
			Generation          uint64 `json:"generation"`
			CredentialReference string `json:"credential_reference"`
			RotationGeneration  uint64 `json:"rotation_generation"`
		}
		if err := json.Unmarshal(vector.Resource, &resource); err != nil {
			t.Fatal(err)
		}
		switch resource.Kind {
		case "connector":
			foundConnector = true
			reference := CredentialReference{Reference: resource.CredentialReference, Generation: resource.RotationGeneration}
			if err := reference.validate(resource.ID); err != nil {
				t.Fatalf("canonical connector credential reference: %v", err)
			}
		case "tunnel_config_snapshot":
			foundSnapshot = true
			if _, err := NewConfigSnapshot(resource.TunnelID, resource.Generation, vector.Resource); err != nil {
				t.Fatalf("canonical tunnel config snapshot: %v", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundConnector || !foundSnapshot {
		t.Fatalf("contract fixture missing connector=%v tunnel_config_snapshot=%v", foundConnector, foundSnapshot)
	}
}

package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

func TestPreviewTunnelV1HostOwnership(t *testing.T) {
	fixtures, err := os.Open("../../testdata/contracts/preview-tunnel-v1/fixtures/resources.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer fixtures.Close()

	seenPreview, seenConnector := false, false
	scanner := bufio.NewScanner(fixtures)
	for scanner.Scan() {
		var vector struct {
			Case     string         `json:"case"`
			Valid    bool           `json:"valid"`
			Resource map[string]any `json:"resource"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if !vector.Valid {
			continue
		}
		if hasForbiddenCredentialKey(vector.Resource) {
			t.Fatalf("%s: readable resource exposes reusable credential material", vector.Case)
		}
		switch vector.Resource["kind"] {
		case "preview_lease":
			seenPreview = true
			if vector.Resource["persistent"] != false || vector.Resource["owner_device_id"] == "" || vector.Resource["owner_session_id"] == "" {
				t.Fatalf("%s: preview must be foreground-owned and nonpersistent", vector.Case)
			}
		case "connector":
			seenConnector = true
			if vector.Resource["id"] == vector.Resource["tunnel_id"] || vector.Resource["credential_reference"] == "" {
				t.Fatalf("%s: connector session must remain replaceable and reference-only", vector.Case)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !seenPreview || !seenConnector {
		t.Fatalf("missing host-owned vectors: preview=%t connector=%t", seenPreview, seenConnector)
	}
}

func hasForbiddenCredentialKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			switch key {
			case "token", "secret", "private_key", "authorization":
				return true
			}
			if hasForbiddenCredentialKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if hasForbiddenCredentialKey(child) {
				return true
			}
		}
	}
	return false
}

package contracttest

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"

	runtimehealth "github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
)

func TestTelemetryHealthV1HostSnapshotContract(t *testing.T) {
	if runtimehealth.HealthSchemaV1 != "paperboat.health/v1" {
		t.Fatalf("implementation schema = %q", runtimehealth.HealthSchemaV1)
	}

	file, err := os.Open("../../testdata/contracts/telemetry-v1/fixtures/health.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seenValid, seenInvalid := 0, 0
	seenErrors := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var vector struct {
			Case          string         `json:"case"`
			Valid         bool           `json:"valid"`
			ExpectedError string         `json:"expected_error"`
			Snapshot      map[string]any `json:"snapshot"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &vector); err != nil {
			t.Fatal(err)
		}
		if vector.Case == "" {
			t.Fatal("telemetry vector has no case")
		}
		if vector.Valid {
			seenValid++
			if len(vector.Snapshot) > 0 {
				assertTelemetrySnapshotShape(t, vector.Snapshot)
			}
		} else {
			seenInvalid++
			if vector.ExpectedError == "" {
				t.Errorf("%s has no expected error", vector.Case)
			}
			seenErrors[vector.ExpectedError] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seenValid < 2 || seenInvalid != 8 {
		t.Fatalf("fixture coverage valid=%d invalid=%d", seenValid, seenInvalid)
	}
	for _, expected := range []string{
		"secret_field_forbidden", "hostname_or_url_forbidden", "unknown_dimension", "unknown_status",
		"retry_mismatch", "broken_state_mismatch", "missing_required_field", "unknown_property",
	} {
		if !seenErrors[expected] {
			t.Errorf("missing negative case %q", expected)
		}
	}

	tracker, err := runtimehealth.NewHealthTracker(func() time.Time {
		return time.Date(2026, 8, 31, 0, 0, 0, 0, time.FixedZone("test", 5*60*60+30*60))
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := tracker.Snapshot()
	body, err := snapshot.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	assertTelemetrySnapshotShape(t, decoded)
	if regexp.MustCompile(`(?i)(authorization|cookie|bearer|private key|https?://)`).Match(body) {
		t.Fatalf("implementation snapshot contains unsafe text: %s", body)
	}
}

func assertTelemetrySnapshotShape(t *testing.T, snapshot map[string]any) {
	t.Helper()
	wantRoot := map[string]bool{"schema": true, "updated_at": true, "overall": true, "dimensions": true, "etag": true}
	if len(snapshot) != len(wantRoot) {
		t.Fatalf("snapshot root keys = %v", mapKeys(snapshot))
	}
	for key := range wantRoot {
		if _, ok := snapshot[key]; !ok {
			t.Fatalf("snapshot missing root key %q", key)
		}
	}
	if snapshot["schema"] != "paperboat.health/v1" {
		t.Fatalf("snapshot schema = %v", snapshot["schema"])
	}
	etag, ok := snapshot["etag"].(string)
	if !ok || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(etag) {
		t.Fatalf("snapshot etag = %v", snapshot["etag"])
	}
	dimensions, ok := snapshot["dimensions"].(map[string]any)
	if !ok {
		t.Fatalf("dimensions = %T", snapshot["dimensions"])
	}
	wantDimensions := []string{"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update"}
	if len(dimensions) != len(wantDimensions) {
		t.Fatalf("dimensions keys = %v", mapKeys(dimensions))
	}
	for _, dimension := range wantDimensions {
		if _, ok := dimensions[dimension]; !ok {
			t.Fatalf("missing dimension %q", dimension)
		}
	}
}

func mapKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	return keys
}

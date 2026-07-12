package telemetry

import (
	"strings"
	"testing"
)

func TestEventValidationAllowsCorrelationMetadata(t *testing.T) {
	e := Event{Name: "upload.result", RequestID: "req_1", ProjectID: "prj_1", EnvironmentID: "env_1", SessionID: "ses_1", Outcome: "accepted", SizeBytes: 42, LatencyMS: 8}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEventValidationRejectsSecretsAndPaths(t *testing.T) {
	for _, value := range []string{"Bearer secret", "/workspace/image.png", "https://example.test", "a\nsecret"} {
		e := Event{Name: "upload.result", Stage: value}
		if err := e.Validate(); err == nil || strings.Contains(err.Error(), value) {
			t.Fatalf("value %q was accepted or echoed: %v", value, err)
		}
	}
}

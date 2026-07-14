// Package telemetry contains the CLI's metadata-only observability boundary.
// It deliberately has no network exporter: the control plane owns event
// ingestion and transport contracts.
package telemetry

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Event struct {
	Name          string    `json:"name"`
	At            time.Time `json:"at"`
	RequestID     string    `json:"request_id,omitempty"`
	ProjectID     string    `json:"project_id,omitempty"`
	EnvironmentID string    `json:"environment_id,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	Stage         string    `json:"stage,omitempty"`
	SizeBytes     int64     `json:"size_bytes,omitempty"`
	LatencyMS     int64     `json:"latency_ms,omitempty"`
	Count         int64     `json:"count,omitempty"`
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

// Validate rejects fields that could carry secrets or user content. Event
// values are identifiers and bounded numeric metadata only.
func (e Event) Validate() error {
	if strings.TrimSpace(e.Name) == "" || !idPattern.MatchString(e.Name) {
		return fmt.Errorf("invalid event name")
	}
	for label, value := range map[string]string{"request_id": e.RequestID, "project_id": e.ProjectID, "environment_id": e.EnvironmentID, "session_id": e.SessionID, "outcome": e.Outcome, "stage": e.Stage} {
		if value != "" && !idPattern.MatchString(value) {
			return fmt.Errorf("invalid %s", label)
		}
	}
	if e.SizeBytes < 0 || e.LatencyMS < 0 || e.Count < 0 {
		return fmt.Errorf("negative event measurement")
	}
	return nil
}

// Sink receives validated metadata events. Implementations must not add raw
// request/response bodies, credentials, URLs, terminal bytes, or file paths.
type Sink interface{ Record(Event) }

type NopSink struct{}

func (NopSink) Record(Event) {}

package diagnostics

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const EventSchemaV1 = "paperboat.diagnostic-event/v1"

var ErrInvalid = errors.New("invalid diagnostic event")

var allowedFields = map[string]bool{
	"capability": true, "generation": true, "operation": true, "outcome": true,
	"path_category": true, "phase": true, "reason": true, "relay_region": true,
	"retry_class": true, "state": true, "transport": true,
}

type Event struct {
	Schema   string            `json:"schema"`
	At       time.Time         `json:"at"`
	Category string            `json:"category"`
	Code     string            `json:"code"`
	Severity string            `json:"severity"`
	Fields   map[string]string `json:"fields,omitempty"`
}

func NewEvent(at time.Time, category, code, severity string, fields map[string]string) (Event, error) {
	event := Event{Schema: EventSchemaV1, At: at.UTC(), Category: category, Code: code, Severity: severity, Fields: cloneFields(fields)}
	if event.Validate() != nil {
		return Event{}, ErrInvalid
	}
	return event, nil
}

func (e Event) Validate() error {
	if e.Schema != EventSchemaV1 || e.At.IsZero() || e.At.Location() != time.UTC || !safeIdentifier(e.Category, 32) || !safeIdentifier(e.Code, 64) || e.Severity != "info" && e.Severity != "warning" && e.Severity != "error" || len(e.Fields) > 12 {
		return ErrInvalid
	}
	for key, value := range e.Fields {
		if !allowedFields[key] || !safeIdentifier(value, 128) {
			return ErrInvalid
		}
	}
	encoded, err := json.Marshal(e)
	if err != nil || len(encoded)+1 > MaximumRecordBytes {
		return ErrInvalid
	}
	return nil
}

func safeIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character)) {
			return false
		}
	}
	return true
}

func cloneEvent(event Event) Event {
	event.Fields = cloneFields(event.Fields)
	return event
}

func cloneFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]string, len(fields))
	for key, value := range fields {
		result[key] = value
	}
	return result
}

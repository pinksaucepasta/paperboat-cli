package localapi

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

const (
	DiagnosticSnapshotSchemaV1 = "paperboat.diagnostics/v1"
	BugreportMarkerSchemaV1    = "paperboat.bugreport-marker/v1"
)

type DiagnosticSnapshot struct {
	Schema         string              `json:"schema"`
	ObservedAt     time.Time           `json:"observed_at"`
	Recent         []diagnostics.Event `json:"recent"`
	DroppedRecords uint64              `json:"dropped_records"`
	DroppedBytes   uint64              `json:"dropped_bytes"`
}

func (s DiagnosticSnapshot) Validate() error {
	if s.Schema != DiagnosticSnapshotSchemaV1 || s.ObservedAt.IsZero() || s.ObservedAt.Location() != time.UTC || len(s.Recent) > diagnostics.MemoryCapacity {
		return ErrInvalidResponse
	}
	for _, event := range s.Recent {
		if event.Validate() != nil {
			return ErrInvalidResponse
		}
	}
	return nil
}

type BugreportMarker struct {
	Schema string `json:"schema"`
	Phase  string `json:"phase"`
}

func (m BugreportMarker) Validate() error {
	if m.Schema != BugreportMarkerSchemaV1 || m.Phase != "start" && m.Phase != "end" {
		return ErrInvalidResponse
	}
	return nil
}

type DiagnosticService interface {
	Diagnostics(context.Context) (DiagnosticSnapshot, error)
	RecordBugreportMarker(context.Context, string) error
	CreateBugreport(context.Context) (diagnostics.Bundle, error)
}

//go:build darwin || linux

package localdaemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type diagnosticService struct {
	recorder  *diagnostics.Recorder
	store     *localapi.SnapshotStore
	stateRoot string
	ownerUID  int
	clock     func() time.Time
}

func (s *diagnosticService) Diagnostics(context.Context) (localapi.DiagnosticSnapshot, error) {
	stats := s.recorder.Stats()
	return localapi.DiagnosticSnapshot{Schema: localapi.DiagnosticSnapshotSchemaV1, ObservedAt: s.clock().UTC(), Recent: s.recorder.Recent(), DroppedRecords: stats.DroppedRecords, DroppedBytes: stats.DroppedBytes}, nil
}

func (s *diagnosticService) RecordBugreportMarker(_ context.Context, phase string) error {
	return s.recorder.Record("bugreport", "reproduction_marker", "info", map[string]string{"phase": phase})
}

func (s *diagnosticService) CreateBugreport(ctx context.Context) (diagnostics.Bundle, error) {
	snapshot, err := s.store.Snapshot(ctx)
	if err != nil {
		return diagnostics.Bundle{}, err
	}
	status, err := json.Marshal(snapshot)
	if err != nil {
		return diagnostics.Bundle{}, err
	}
	return diagnostics.CreateBundle(ctx, diagnostics.BundleConfig{Directory: filepath.Join(s.stateRoot, "bugreports"), OwnerUID: s.ownerUID, Recorder: s.recorder, Status: status, Clock: s.clock})
}

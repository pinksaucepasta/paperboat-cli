//go:build darwin || linux || windows

package runtime

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/availability"
)

func TestRuntimeUpdateObservationUsesPlatformChannelAndFences(t *testing.T) {
	now := time.Now().UTC()
	sender := &runtimeObservationSender{reporterVersion: "2026.08.20.12", installationGeneration: 4, workerGeneration: 9, osBootID: "boot-1"}
	observation := sender.updateObservation(now, &availability.Observation{UpdateHealth: "healthy", UpdateRollbacks: 2})
	if observation == nil || observation.State != "healthy" || observation.CurrentVersion != "2026.08.20.12" || observation.InstallationGeneration != 4 || observation.WorkerGeneration != 9 || observation.OSBootID != "boot-1" || observation.RollbackCount != 2 || observation.ObservedAt != now || observation.OperationID == "" {
		t.Fatalf("observation=%+v", observation)
	}
	wantChannel := "stable"
	if observation.Channel != wantChannel {
		t.Fatalf("channel=%q want %q", observation.Channel, wantChannel)
	}
	recovery := sender.updateObservation(now, &availability.Observation{UpdateHealth: "recovery_required"})
	if recovery == nil || recovery.State != "failed" || recovery.TargetVersion != sender.reporterVersion || recovery.ErrorCode != "recovery_required" {
		t.Fatalf("recovery observation=%+v", recovery)
	}
	if got := sender.updateObservation(now, &availability.Observation{UpdateHealth: "unknown"}); got != nil {
		t.Fatalf("unknown updater emitted observation=%+v", got)
	}
}

func TestRuntimeUpdateObservationReportsWithoutAvailabilityService(t *testing.T) {
	now := time.Now().UTC()
	sender := &runtimeObservationSender{
		reporterVersion:        "2026.08.20.12",
		installationGeneration: 4,
		workerGeneration:       9,
		osBootID:               "boot-1",
	}
	observation := sender.updateObservation(now, nil)
	if observation == nil {
		t.Fatal("client observation is nil without an availability service")
	}
	if observation.State != "healthy" || observation.RollbackCount != 0 || observation.CurrentVersion != sender.reporterVersion {
		t.Fatalf("client observation=%+v", observation)
	}
}

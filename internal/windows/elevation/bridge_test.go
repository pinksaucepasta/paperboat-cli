package elevation

import (
	"testing"
	"time"
)

func TestOperationDurationBoundsRuntimeActivation(t *testing.T) {
	for _, action := range []string{ActionInstall, ActionInstallCommit, ActionCommit, ActionUninstall, ActionStop} {
		if got := operationDuration(OperationRuntimeService, action); got != RuntimeActivationDuration {
			t.Fatalf("runtime action %q duration = %s, want %s", action, got, RuntimeActivationDuration)
		}
	}
	if got := operationDuration(OperationRuntimeService, ActionRepair); got != MaxOperationDuration {
		t.Fatalf("repair duration = %s, want maintenance duration %s", got, MaxOperationDuration)
	}
	if RuntimeActivationDuration <= 0 || RuntimeActivationDuration >= MaxOperationDuration || RuntimeActivationDuration > 90*time.Second {
		t.Fatalf("invalid runtime activation duration %s", RuntimeActivationDuration)
	}
}

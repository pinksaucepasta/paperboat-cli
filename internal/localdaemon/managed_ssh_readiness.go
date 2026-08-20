package localdaemon

import (
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

const managedSSHDoctorRecovery = "Run pb ssh doctor <machine>."

// managedSSHReadinessSource lets the daemon publish local managed-SSH startup
// state without coupling inventory to the authenticated control-plane source.
type managedSSHReadinessSource interface {
	SetManagedSSHReadiness(ready bool, code string)
}

func reportManagedSSHStartup(source MachineSource, recorder *diagnostics.Recorder, startupErr error) {
	readiness, ok := source.(managedSSHReadinessSource)
	if !ok {
		return
	}
	if startupErr == nil {
		readiness.SetManagedSSHReadiness(true, "")
		return
	}
	code := ManagedSSHHealthCode(startupErr)
	readiness.SetManagedSSHReadiness(false, code)
	// Do not record startupErr: it can contain operating-system or credential
	// details. The typed code and recovery action are sufficient for support.
	_ = recorder.Record("ssh", "managed_startup", "warning", map[string]string{
		"outcome": "degraded",
		"reason":  code,
	})
}

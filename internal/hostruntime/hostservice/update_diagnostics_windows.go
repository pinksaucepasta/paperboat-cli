//go:build windows

package hostservice

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsUpdaterStateSchema = "paperboat.windows-updated/v1"

type windowsUpdateDiagnostics struct {
	statePath string
	machineID string
	running   func() bool
}

// NewWindowsUpdateDiagnostics bridges the independently managed updater into
// host observations without coupling power-policy success to updater startup.
func NewWindowsUpdateDiagnostics(stateRoot, machineID string) (UpdateDiagnostics, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || strings.TrimSpace(machineID) == "" {
		return nil, ErrInvalidConfig
	}
	return &windowsUpdateDiagnostics{
		statePath: filepath.Join(stateRoot, "service-state.json"),
		machineID: machineID,
		running:   windowsUpdaterRunning,
	}, nil
}

func (*windowsUpdateDiagnostics) RollbackCount() uint64 { return 0 }

func (d *windowsUpdateDiagnostics) UpdateHealth() string {
	if d == nil || d.running == nil || !d.running() || !d.validState() {
		return "recovery_required"
	}
	return "healthy"
}

func (d *windowsUpdateDiagnostics) validState() bool {
	body, err := os.ReadFile(d.statePath)
	if err != nil || len(body) == 0 || len(body) > 16<<10 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state struct {
		Schema      string    `json:"schema"`
		MachineID   string    `json:"machine_id"`
		RecoveredAt time.Time `json:"recovered_at"`
	}
	var extra any
	return decoder.Decode(&state) == nil && decoder.Decode(&extra) == io.EOF && state.Schema == windowsUpdaterStateSchema && state.MachineID == d.machineID && !state.RecoveredAt.IsZero() && !state.RecoveredAt.After(time.Now().UTC().Add(time.Minute))
}

func windowsUpdaterRunning() bool {
	manager, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer manager.Disconnect()
	serviceHandle, err := manager.OpenService("PaperboatUpdated")
	if err != nil {
		return false
	}
	defer serviceHandle.Close()
	status, err := serviceHandle.Query()
	return err == nil && status.State == svc.Running
}

var _ UpdateDiagnostics = (*windowsUpdateDiagnostics)(nil)

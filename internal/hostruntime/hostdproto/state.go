package hostdproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const stateSchemaV1 = "paperboat.hostd-fence/v1"

// FenceState is the non-secret crash-recovery record. Worker leases are never
// persisted: after a hostd restart every worker must negotiate a fresh lease.
type FenceState struct {
	Schema     string `json:"schema"`
	WorkerID   string `json:"worker_id"`
	APIVersion uint16 `json:"api_version"`
	Epoch      uint64 `json:"epoch"`
}

func LoadFenceState(path string) (FenceState, error) {
	if !filepath.IsAbs(path) {
		return FenceState{}, ErrInvalidConfig
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FenceState{Schema: stateSchemaV1}, nil
	}
	if err != nil {
		return FenceState{}, fmt.Errorf("read hostd fence state: %w", err)
	}
	var state FenceState
	if err := decodeStrict(data, &state); err != nil || state.Schema != stateSchemaV1 {
		return FenceState{}, ErrInvalidFrame
	}
	if state.Epoch == 0 {
		if state.WorkerID != "" || state.APIVersion != 0 {
			return FenceState{}, ErrInvalidFrame
		}
	} else if !validWorkerID(state.WorkerID) || !validAPIVersion(state.APIVersion) {
		return FenceState{}, ErrInvalidFrame
	}
	return state, nil
}

func NewFenceStatePersister(path string, ownerUID, ownerGID int) func(Status) error {
	return func(status Status) error {
		if status.State != StateActive || status.validate() != nil {
			return ErrInvalidFrame
		}
		encoded, err := json.Marshal(FenceState{
			Schema: stateSchemaV1, WorkerID: status.WorkerID,
			APIVersion: status.APIVersion, Epoch: status.Epoch,
		})
		if err != nil {
			return err
		}
		return atomicfile.Write(path, append(encoded, '\n'), atomicfile.Options{
			Mode: 0o600, OwnerUID: ownerUID, OwnerGID: ownerGID,
		})
	}
}

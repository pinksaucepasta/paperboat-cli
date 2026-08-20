//go:build windows

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

const workerBootSchemaV1 = "paperboat.worker-boot/v1"

type workerBootState struct {
	Schema     string    `json:"schema"`
	OSBootID   string    `json:"os_boot_id"`
	Generation uint64    `json:"generation"`
	StartedAt  time.Time `json:"started_at"`
}

// Windows exposes a monotonic tick count rather than a boot UUID. Subtracting
// it from the current wall clock yields a stable boot epoch; truncation avoids
// sub-millisecond sampling differences across runtime restarts.
func operatingSystemBootID() (string, error) {
	if uptime := windowsGetTickCount64(); uptime > 0 {
		boot := time.Now().UTC().Add(-time.Duration(uptime) * time.Millisecond).Truncate(time.Second)
		return strconv.FormatInt(boot.Unix(), 10), nil
	}
	return "", ErrProductionInvalid
}

var getTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func windowsGetTickCount64() uint64 {
	value, _, _ := syscall.SyscallN(getTickCount64.Addr())
	return uint64(value)
}

func recordWorkerBoot(stateRoot string) (workerBootState, string, error) {
	bootID, err := operatingSystemBootID()
	if err != nil {
		return workerBootState{}, "", err
	}
	path := filepath.Join(stateRoot, "runtime", "worker-boot.json")
	previous, loadErr := loadWorkerBoot(path)
	reason := "runtime_restart"
	if loadErr == nil && previous.OSBootID != bootID {
		reason = "machine_reboot"
	} else if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return workerBootState{}, "", loadErr
	}
	next := workerBootState{Schema: workerBootSchemaV1, OSBootID: bootID, Generation: previous.Generation + 1, StartedAt: time.Now().UTC()}
	if err := writeWorkerBoot(path, next); err != nil {
		return workerBootState{}, "", err
	}
	return next, reason, nil
}

func loadWorkerBoot(path string) (workerBootState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return workerBootState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4096 {
		return workerBootState{}, ErrProductionInvalid
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return workerBootState{}, ErrProductionInvalid
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return workerBootState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state workerBootState
	var extra any
	if decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF || state.Schema != workerBootSchemaV1 || state.OSBootID == "" || state.Generation < 1 || state.StartedAt.IsZero() {
		return workerBootState{}, ErrProductionInvalid
	}
	return state, nil
}

func writeWorkerBoot(path string, state workerBootState) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProductionInvalid
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(directory))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrProductionInvalid
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

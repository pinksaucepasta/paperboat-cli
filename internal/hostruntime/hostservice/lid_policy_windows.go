//go:build windows

package hostservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

const windowsPowerBaselineSchema = "paperboat.windows-power-baseline/v1"

var (
	powerProfileDLL         = windows.NewLazySystemDLL("powrprof.dll")
	powerGetActiveScheme    = powerProfileDLL.NewProc("PowerGetActiveScheme")
	powerReadACValueIndex   = powerProfileDLL.NewProc("PowerReadACValueIndex")
	powerReadDCValueIndex   = powerProfileDLL.NewProc("PowerReadDCValueIndex")
	powerWriteACValueIndex  = powerProfileDLL.NewProc("PowerWriteACValueIndex")
	powerWriteDCValueIndex  = powerProfileDLL.NewProc("PowerWriteDCValueIndex")
	powerSetActiveScheme    = powerProfileDLL.NewProc("PowerSetActiveScheme")
	windowsButtonsSubgroup  = mustWindowsGUID("{4f971e89-eebd-4455-a8de-9e59040e7347}")
	windowsLidActionSetting = mustWindowsGUID("{5ca83367-6e45-459f-a27b-476b1d01c936}")
)

type windowsPowerBaseline struct {
	Schema string `json:"schema"`
	Scheme string `json:"scheme"`
	AC     uint32 `json:"ac"`
	DC     uint32 `json:"dc"`
}

type powerSchemeAPI interface {
	Current() (windows.GUID, error)
	Read(windows.GUID) (uint32, uint32, error)
	Write(windows.GUID, uint32, uint32) error
}

type lidPolicy interface {
	KeepAwake() error
	Restore() error
}

type windowsLidPolicy struct {
	baselinePath string
	power        powerSchemeAPI
}

func newWindowsLidPolicy(path string) lidPolicy {
	return &windowsLidPolicy{baselinePath: path, power: nativePowerSchemeAPI{}}
}

func (p *windowsLidPolicy) KeepAwake() error {
	baseline, err := p.loadBaseline()
	if errors.Is(err, os.ErrNotExist) {
		baseline, err = p.captureCurrentBaseline()
	} else if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	scheme, err := windows.GUIDFromString(baseline.Scheme)
	if err != nil {
		return ErrInvalidConfig
	}
	current, err := p.power.Current()
	if err != nil {
		return err
	}
	if current != scheme {
		// A user-selected power scheme wins. Restore the old scheme without
		// activating it, then capture and protect the newly active scheme.
		if err := p.restoreBaseline(baseline, scheme); err != nil {
			return err
		}
		baseline, err = p.captureCurrentBaseline()
		if err != nil {
			return err
		}
		scheme, err = windows.GUIDFromString(baseline.Scheme)
		if err != nil {
			return ErrInvalidConfig
		}
	}
	return p.power.Write(scheme, 0, 0)
}

func (p *windowsLidPolicy) Restore() error {
	baseline, err := p.loadBaseline()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	scheme, err := windows.GUIDFromString(baseline.Scheme)
	if err != nil {
		return ErrInvalidConfig
	}
	return p.restoreBaseline(baseline, scheme)
}

func (p *windowsLidPolicy) captureCurrentBaseline() (windowsPowerBaseline, error) {
	scheme, err := p.power.Current()
	if err != nil {
		return windowsPowerBaseline{}, err
	}
	ac, dc, err := p.power.Read(scheme)
	if err != nil {
		return windowsPowerBaseline{}, err
	}
	baseline := windowsPowerBaseline{Schema: windowsPowerBaselineSchema, Scheme: scheme.String(), AC: ac, DC: dc}
	return baseline, p.writeBaseline(baseline)
}

func (p *windowsLidPolicy) restoreBaseline(baseline windowsPowerBaseline, scheme windows.GUID) error {
	if err := p.power.Write(scheme, baseline.AC, baseline.DC); err != nil {
		return err
	}
	return os.Remove(p.baselinePath)
}

func (p *windowsLidPolicy) writeBaseline(baseline windowsPowerBaseline) error {
	if !filepath.IsAbs(p.baselinePath) || filepath.Clean(p.baselinePath) != p.baselinePath {
		return ErrInvalidConfig
	}
	body, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	return atomicfile.Write(p.baselinePath, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func (p *windowsLidPolicy) loadBaseline() (windowsPowerBaseline, error) {
	info, err := os.Lstat(p.baselinePath)
	if err != nil {
		return windowsPowerBaseline{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return windowsPowerBaseline{}, ErrInvalidConfig
	}
	body, err := os.ReadFile(p.baselinePath)
	if err != nil {
		return windowsPowerBaseline{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var baseline windowsPowerBaseline
	var extra any
	if decoder.Decode(&baseline) != nil || decoder.Decode(&extra) != io.EOF || baseline.Schema != windowsPowerBaselineSchema || baseline.Scheme == "" || baseline.AC > 3 || baseline.DC > 3 {
		return windowsPowerBaseline{}, ErrInvalidConfig
	}
	if _, err := windows.GUIDFromString(baseline.Scheme); err != nil {
		return windowsPowerBaseline{}, ErrInvalidConfig
	}
	return baseline, nil
}

type nativePowerSchemeAPI struct{}

func (nativePowerSchemeAPI) Current() (windows.GUID, error) {
	var scheme *windows.GUID
	result, _, _ := powerGetActiveScheme.Call(0, uintptr(unsafe.Pointer(&scheme)))
	if result != 0 {
		return windows.GUID{}, syscall.Errno(result)
	}
	if scheme == nil {
		return windows.GUID{}, errors.New("PowerGetActiveScheme returned no scheme")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(scheme)))
	return *scheme, nil
}

func (nativePowerSchemeAPI) Read(scheme windows.GUID) (uint32, uint32, error) {
	var ac, dc uint32
	if err := powerReadIndex(powerReadACValueIndex, scheme, &ac); err != nil {
		return 0, 0, err
	}
	if err := powerReadIndex(powerReadDCValueIndex, scheme, &dc); err != nil {
		return 0, 0, err
	}
	return ac, dc, nil
}

func (nativePowerSchemeAPI) Write(scheme windows.GUID, ac, dc uint32) error {
	if err := powerWriteIndex(powerWriteACValueIndex, scheme, ac); err != nil {
		return err
	}
	if err := powerWriteIndex(powerWriteDCValueIndex, scheme, dc); err != nil {
		return err
	}
	current, err := (nativePowerSchemeAPI{}).Current()
	if err != nil {
		return err
	}
	if current != scheme {
		return nil
	}
	result, _, _ := powerSetActiveScheme.Call(0, uintptr(unsafe.Pointer(&scheme)))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func powerReadIndex(proc *windows.LazyProc, scheme windows.GUID, value *uint32) error {
	result, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&scheme)), uintptr(unsafe.Pointer(&windowsButtonsSubgroup)), uintptr(unsafe.Pointer(&windowsLidActionSetting)), uintptr(unsafe.Pointer(value)))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func powerWriteIndex(proc *windows.LazyProc, scheme windows.GUID, value uint32) error {
	result, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&scheme)), uintptr(unsafe.Pointer(&windowsButtonsSubgroup)), uintptr(unsafe.Pointer(&windowsLidActionSetting)), uintptr(value))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func mustWindowsGUID(value string) windows.GUID {
	result, err := windows.GUIDFromString(value)
	if err != nil {
		panic(err)
	}
	return result
}

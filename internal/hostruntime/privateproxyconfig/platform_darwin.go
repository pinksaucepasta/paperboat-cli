//go:build darwin

package privateproxyconfig

import (
	"path/filepath"
)

func NewPlatformManager(stateRoot string) (*Manager, error) {
	return New(filepath.Join(stateRoot, "private-access", "system-proxy.json"), NewMacOSAdapter(ExecRunner{}))
}

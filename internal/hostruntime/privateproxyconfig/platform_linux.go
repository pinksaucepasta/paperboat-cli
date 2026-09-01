//go:build linux

package privateproxyconfig

import (
	"os"
	"path/filepath"
)

func NewPlatformManager(stateRoot string) (*Manager, error) {
	return New(filepath.Join(stateRoot, "private-access", "system-proxy.json"), NewLinuxAdapter(ExecRunner{}, os.Getenv))
}

//go:build windows

package localapi

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Paths is the per-user local API layout. Windows uses a named pipe for the
// API endpoint and LocalAppData Known Folder for state. This avoids trusting a
// caller-controlled environment variable for the local security boundary.
type Paths struct {
	StateRoot   string
	RuntimeRoot string
	SocketPath  string
	LockPath    string
}

func CurrentPaths(uid int) (Paths, error) {
	if uid < 0 {
		return Paths{}, ErrInvalidConfig
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return Paths{}, ErrInvalidConfig
	}
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return Paths{}, ErrInvalidConfig
	}
	stateRoot := filepath.Join(filepath.Clean(base), "Paperboat", "state")
	runtimeRoot := filepath.Join(stateRoot, "run")
	return Paths{
		StateRoot:   stateRoot,
		RuntimeRoot: runtimeRoot,
		SocketPath:  `\\.\pipe\paperboat-local-api`,
		LockPath:    filepath.Join(stateRoot, "daemon.lock"),
	}, nil
}

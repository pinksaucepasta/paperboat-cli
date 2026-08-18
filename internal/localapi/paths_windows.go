//go:build windows

package localapi

import (
	"os"
	"path/filepath"
)

// Paths is the per-user local API layout. Windows uses a named pipe for the
// API endpoint. The Windows service and broker implementation will populate
// this endpoint in a later platform-hardening pass; keeping the layout here
// gives every Windows build one stable path contract in the meantime.
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
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return Paths{}, ErrInvalidConfig
		}
	}
	if !filepath.IsAbs(base) {
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

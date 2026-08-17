package service

import (
	"path/filepath"
	"strings"
)

// Layout is the fixed, root-owned layout used by split Paperboat host
// installations. It deliberately does not expose a caller-provided install
// root: accepting one would turn the privileged updater into a generic file
// writer. All mutable release selection happens by atomic replacement within
// ReleasesRoot, never by changing a service definition.
type Layout struct {
	Platform string

	InstallRoot   string
	ReleasesRoot  string
	HostdBinary   string
	UpdaterBinary string
	Launcher      string

	RuntimeCurrent  string
	RuntimeRollback string
	RuntimeStaged   string
	CLICurrent      string
	CLIRollback     string

	UpdateStateRoot string
	HostdSocket     string
}

// DefaultLayout returns only supported native host layouts. Windows has no
// implementation here because a service definition without its required pipe
// ACL and service-token enforcement would be a misleading, unsafe stub.
func DefaultLayout(platform string) (Layout, error) {
	var installRoot, updateStateRoot, socketRoot string
	switch platform {
	case "linux":
		installRoot = "/usr/local/libexec/paperboat"
		updateStateRoot = "/var/lib/paperboat-updated"
		socketRoot = "/run/paperboat-hostd"
	case "darwin":
		installRoot = "/Library/PrivilegedHelperTools/Paperboat"
		updateStateRoot = "/Library/Application Support/Paperboat/updated"
		socketRoot = "/var/run/paperboat-hostd"
	default:
		return Layout{}, ErrUnsupportedPlatform
	}
	releasesRoot := filepath.Join(installRoot, "releases")
	layout := Layout{
		Platform: platform,

		InstallRoot:   installRoot,
		ReleasesRoot:  releasesRoot,
		HostdBinary:   filepath.Join(installRoot, "components", "paperboat-hostd"),
		UpdaterBinary: filepath.Join(installRoot, "components", "paperboat-updated"),
		Launcher:      filepath.Join(installRoot, "launcher", "pb"),

		RuntimeCurrent:  filepath.Join(releasesRoot, "runtime-current", "paperboat-runtime"),
		RuntimeRollback: filepath.Join(releasesRoot, "runtime-rollback", "paperboat-runtime"),
		RuntimeStaged:   filepath.Join(releasesRoot, "runtime-staged", "paperboat-runtime"),
		CLICurrent:      filepath.Join(releasesRoot, "cli-current", "pb"),
		CLIRollback:     filepath.Join(releasesRoot, "cli-rollback", "pb"),

		UpdateStateRoot: updateStateRoot,
		HostdSocket:     filepath.Join(socketRoot, "hostd.sock"),
	}
	if err := layout.Validate(); err != nil {
		return Layout{}, err
	}
	return layout, nil
}

func (l Layout) Validate() error {
	if l.Platform != "linux" && l.Platform != "darwin" {
		return ErrUnsupportedPlatform
	}
	for _, path := range []string{
		l.InstallRoot, l.ReleasesRoot, l.HostdBinary, l.UpdaterBinary, l.Launcher,
		l.RuntimeCurrent, l.RuntimeRollback, l.RuntimeStaged, l.CLICurrent, l.CLIRollback,
		l.UpdateStateRoot, l.HostdSocket,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrInvalidDefinition
		}
	}
	if filepath.Dir(l.HostdSocket) == l.UpdateStateRoot || filepath.Dir(l.HostdSocket) == l.ReleasesRoot {
		return ErrInvalidDefinition
	}
	for _, path := range []string{l.RuntimeCurrent, l.RuntimeRollback, l.RuntimeStaged, l.CLICurrent, l.CLIRollback} {
		if !within(l.ReleasesRoot, path) {
			return ErrInvalidDefinition
		}
	}
	if !within(l.InstallRoot, l.ReleasesRoot) || !within(l.InstallRoot, l.HostdBinary) || !within(l.InstallRoot, l.UpdaterBinary) || !within(l.InstallRoot, l.Launcher) {
		return ErrInvalidDefinition
	}
	if l.RuntimeCurrent == l.RuntimeRollback || l.RuntimeCurrent == l.RuntimeStaged || l.RuntimeRollback == l.RuntimeStaged || l.CLICurrent == l.CLIRollback {
		return ErrInvalidDefinition
	}
	return nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

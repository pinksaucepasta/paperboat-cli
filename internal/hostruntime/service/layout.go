package service

import (
	"path"
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

// DefaultLayout returns the fixed, supported native host layout. Windows uses
// a named pipe rather than pretending a filesystem socket is secure there.
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
	case "windows":
		installRoot = `C:\Program Files\Paperboat`
		updateStateRoot = `C:\ProgramData\Paperboat\updated`
		socketRoot = `\\.\pipe\Paperboat`
	default:
		return Layout{}, ErrUnsupportedPlatform
	}
	join := path.Join
	if platform == "windows" {
		join = windowsPathJoin
	}
	releasesRoot := join(installRoot, "releases")
	layout := Layout{
		Platform: platform,

		InstallRoot:   installRoot,
		ReleasesRoot:  releasesRoot,
		HostdBinary:   join(installRoot, "components", "paperboat-hostd"),
		UpdaterBinary: join(installRoot, "components", "paperboat-updated"),
		Launcher:      join(installRoot, "launcher", "pb"),

		RuntimeCurrent:  join(releasesRoot, "runtime-current", "paperboat-runtime"),
		RuntimeRollback: join(releasesRoot, "runtime-rollback", "paperboat-runtime"),
		RuntimeStaged:   join(releasesRoot, "runtime-staged", "paperboat-runtime"),
		CLICurrent:      join(releasesRoot, "cli-current", "pb"),
		CLIRollback:     join(releasesRoot, "cli-rollback", "pb"),

		UpdateStateRoot: updateStateRoot,
		HostdSocket:     join(socketRoot, "hostd.sock"),
	}
	if platform == "windows" {
		layout.HostdBinary += ".exe"
		layout.UpdaterBinary += ".exe"
		layout.Launcher += ".exe"
		layout.RuntimeCurrent += ".exe"
		layout.RuntimeRollback += ".exe"
		layout.RuntimeStaged += ".exe"
		layout.CLICurrent += ".exe"
		layout.CLIRollback += ".exe"
		layout.HostdSocket = `\\.\pipe\PaperboatHostd`
	}
	if err := layout.Validate(); err != nil {
		return Layout{}, err
	}
	return layout, nil
}

func (l Layout) Validate() error {
	if l.Platform != "linux" && l.Platform != "darwin" && l.Platform != "windows" {
		return ErrUnsupportedPlatform
	}
	for _, path := range []string{
		l.InstallRoot, l.ReleasesRoot, l.HostdBinary, l.UpdaterBinary, l.Launcher,
		l.RuntimeCurrent, l.RuntimeRollback, l.RuntimeStaged, l.CLICurrent, l.CLIRollback,
		l.UpdateStateRoot, l.HostdSocket,
	} {
		if !absoluteForPlatform(l.Platform, path) {
			return ErrInvalidDefinition
		}
	}
	if l.Platform != "windows" && (filepath.Dir(l.HostdSocket) == l.UpdateStateRoot || filepath.Dir(l.HostdSocket) == l.ReleasesRoot) {
		return ErrInvalidDefinition
	}
	for _, path := range []string{l.RuntimeCurrent, l.RuntimeRollback, l.RuntimeStaged, l.CLICurrent, l.CLIRollback} {
		if !withinForPlatform(l.Platform, l.ReleasesRoot, path) {
			return ErrInvalidDefinition
		}
	}
	if !withinForPlatform(l.Platform, l.InstallRoot, l.ReleasesRoot) || !withinForPlatform(l.Platform, l.InstallRoot, l.HostdBinary) || !withinForPlatform(l.Platform, l.InstallRoot, l.UpdaterBinary) || !withinForPlatform(l.Platform, l.InstallRoot, l.Launcher) {
		return ErrInvalidDefinition
	}
	if l.RuntimeCurrent == l.RuntimeRollback || l.RuntimeCurrent == l.RuntimeStaged || l.RuntimeRollback == l.RuntimeStaged || l.CLICurrent == l.CLIRollback {
		return ErrInvalidDefinition
	}
	return nil
}

func absoluteForPlatform(platform, value string) bool {
	if platform != "windows" {
		return pathpkgIsCleanAbsolute(value)
	}
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && value[2] == '\\' || strings.HasPrefix(value, `\\.\pipe\`)
}

func windowsPathJoin(elements ...string) string {
	result := ""
	for _, element := range elements {
		if result == "" {
			result = strings.TrimRight(element, `\\`)
			continue
		}
		result += `\` + strings.Trim(element, `\`)
	}
	return result
}

func withinForPlatform(platform, root, value string) bool {
	if platform != "windows" {
		if !pathpkgIsCleanAbsolute(root) || !pathpkgIsCleanAbsolute(value) {
			return false
		}
		root = strings.TrimRight(root, "/") + "/"
		return strings.HasPrefix(value, root)
	}
	root = strings.TrimRight(strings.ToLower(root), `\`) + `\`
	return strings.HasPrefix(strings.ToLower(value), root)
}

func pathpkgIsCleanAbsolute(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

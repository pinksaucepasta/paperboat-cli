package service

import (
	"path"
	"path/filepath"
	"strings"
)

// Layout is the fixed, root-owned layout used by Paperboat host installations.
// There is exactly one executable. Services invoke Binary with an internal
// role argument, and the updater atomically rotates Binary through the two
// release slots below. Callers cannot provide an install root: accepting one
// would turn the privileged updater into a generic file writer.
type Layout struct {
	Platform string

	InstallRoot    string
	ReleasesRoot   string
	Binary         string
	BinaryRollback string
	BinaryStaged   string

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

		InstallRoot:    installRoot,
		ReleasesRoot:   releasesRoot,
		Binary:         join(installRoot, "bin", "pb"),
		BinaryRollback: join(releasesRoot, "pb.rollback"),
		BinaryStaged:   join(releasesRoot, "pb.staged"),

		UpdateStateRoot: updateStateRoot,
		HostdSocket:     join(socketRoot, "hostd.sock"),
	}
	if platform == "windows" {
		layout.Binary += ".exe"
		layout.BinaryRollback += ".exe"
		layout.BinaryStaged += ".exe"
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
		l.InstallRoot, l.ReleasesRoot, l.Binary, l.BinaryRollback, l.BinaryStaged,
		l.UpdateStateRoot, l.HostdSocket,
	} {
		if !absoluteForPlatform(l.Platform, path) {
			return ErrInvalidDefinition
		}
	}
	if l.Platform != "windows" && (filepath.Dir(l.HostdSocket) == l.UpdateStateRoot || filepath.Dir(l.HostdSocket) == l.ReleasesRoot) {
		return ErrInvalidDefinition
	}
	for _, path := range []string{l.BinaryRollback, l.BinaryStaged} {
		if !withinForPlatform(l.Platform, l.ReleasesRoot, path) {
			return ErrInvalidDefinition
		}
	}
	if !withinForPlatform(l.Platform, l.InstallRoot, l.ReleasesRoot) || !withinForPlatform(l.Platform, l.InstallRoot, l.Binary) {
		return ErrInvalidDefinition
	}
	if l.Binary == l.BinaryRollback || l.Binary == l.BinaryStaged || l.BinaryRollback == l.BinaryStaged {
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
			result = strings.TrimRight(element, `\`)
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

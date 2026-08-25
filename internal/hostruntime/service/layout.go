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

// WindowsReleasePaths is one immutable, signed Windows release. SCM services
// point directly at Hostd and Updater in this directory. The stable CLI
// launcher selects CLI through ActiveCLIRecord only after service health has
// been proven.
type WindowsReleasePaths struct {
	Root, Runtime, CLI, Hostd, Updater, Launcher, ActiveCLIRecord string
}

// WindowsRelease returns fixed paths for an exact release version. It accepts
// no arbitrary directory or filename, keeping updater writes inside the
// protected Paperboat release root.
func (l Layout) WindowsRelease(version string) (WindowsReleasePaths, error) {
	if l.Platform != "windows" || !exactLayoutReleaseVersion(version) {
		return WindowsReleasePaths{}, ErrInvalidDefinition
	}
	root := windowsPathJoin(l.ReleasesRoot, "versions", version)
	paths := WindowsReleasePaths{
		Root:            root,
		Runtime:         windowsPathJoin(root, "paperboat-runtime.exe"),
		CLI:             windowsPathJoin(root, "pb.exe"),
		Hostd:           windowsPathJoin(root, "paperboat-hostd.exe"),
		Updater:         windowsPathJoin(root, "paperboat-updater.exe"),
		Launcher:        windowsPathJoin(root, "pb-launcher.exe"),
		ActiveCLIRecord: windowsPathJoin(filepath.Dir(l.CLICurrent), "pb.active"),
	}
	for _, value := range []string{paths.Root, paths.Runtime, paths.CLI, paths.Hostd, paths.Updater, paths.Launcher} {
		if !withinForPlatform("windows", l.ReleasesRoot, value) {
			return WindowsReleasePaths{}, ErrInvalidDefinition
		}
	}
	return paths, nil
}

// WindowsVersionForExecutable returns the immutable release version owning a
// Windows component executable. Mutable bin and legacy slot paths are rejected.
func (l Layout) WindowsVersionForExecutable(executable string) (string, error) {
	if l.Platform != "windows" || !withinForPlatform("windows", windowsPathJoin(l.ReleasesRoot, "versions"), executable) {
		return "", ErrInvalidDefinition
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(filepath.Clean(executable)), strings.ToLower(windowsPathJoin(l.ReleasesRoot, "versions"))), `\`)
	parts := strings.Split(relative, `\`)
	if len(parts) != 2 || !exactLayoutReleaseVersion(parts[0]) {
		return "", ErrInvalidDefinition
	}
	return parts[0], nil
}

func exactLayoutReleaseVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || len(parts[0]) != 4 || len(parts[1]) != 2 || len(parts[2]) != 2 || len(parts[3]) == 0 || len(parts[3]) > 4 || len(parts[3]) > 1 && parts[3][0] == '0' {
		return false
	}
	for _, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
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

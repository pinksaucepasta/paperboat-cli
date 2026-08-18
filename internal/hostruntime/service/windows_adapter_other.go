//go:build !windows

package service

import (
	"context"
)

// These declarations keep the platform-neutral installer and component
// wiring type-safe on Unix. They are never selected for a Unix installation;
// WindowsController's implementation lives in service_windows.go.
type WindowsController struct{}

func (WindowsController) Apply(context.Context, string, bool) error { return ErrUnsupportedPlatform }
func (WindowsController) Remove(context.Context, string) error      { return ErrUnsupportedPlatform }

func safeWindowsServiceKind(kind, instance string) bool {
	if kind == PreviewKind {
		return safeInstance(instance)
	}
	return kind == WorkerKind || kind == HostKind || kind == HostdKind || kind == UpdaterKind || kind == ConfigKind || kind == DaemonKind
}

func windowsServiceName(kind, instance string) string {
	switch kind {
	case HostdKind:
		return "PaperboatHostd"
	case UpdaterKind:
		return "PaperboatUpdated"
	case HostKind:
		return "PaperboatHost"
	case ConfigKind:
		return "PaperboatRuntimeConfig"
	case DaemonKind:
		return "PaperboatLocalDaemon"
	case PreviewKind:
		return "PaperboatPreview-" + instance
	default:
		return "PaperboatRuntime"
	}
}

func renderWindowsService(Config) ([]byte, error) { return nil, ErrUnsupportedPlatform }

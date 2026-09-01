//go:build !windows

package service

import (
	"context"
)

// WindowsController keeps the platform-neutral installer and component wiring
// type-safe on Unix. It is never selected for a Unix installation; its Windows
// implementation lives in service_windows.go.
type WindowsController struct{}

func (WindowsController) Apply(context.Context, string, bool) error { return ErrUnsupportedPlatform }
func (WindowsController) Remove(context.Context, string) error      { return ErrUnsupportedPlatform }
func (WindowsController) Inspect(context.Context, string) (NativeControllerStatus, error) {
	return NativeControllerStatus{}, ErrUnsupportedPlatform
}
func (WindowsController) Enable(context.Context, string) error  { return ErrUnsupportedPlatform }
func (WindowsController) Disable(context.Context, string) error { return ErrUnsupportedPlatform }
func (WindowsController) Start(context.Context, string) error   { return ErrUnsupportedPlatform }
func (WindowsController) Stop(context.Context, string) error    { return ErrUnsupportedPlatform }

func safeWindowsServiceKind(kind, instance string) bool {
	if instance != "" {
		return false
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
	default:
		return "PaperboatRuntime"
	}
}

func renderWindowsService(Config) ([]byte, error) { return nil, ErrUnsupportedPlatform }

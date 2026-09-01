package privateproxyconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const gsettings = "/usr/bin/gsettings"
const gnomeProxySchema = "org.gnome.system.proxy"

type LinuxAdapter struct {
	runner CommandRunner
	getenv func(string) string
}

func NewLinuxAdapter(runner CommandRunner, getenv func(string) string) *LinuxAdapter {
	return &LinuxAdapter{runner: runner, getenv: getenv}
}
func (a *LinuxAdapter) Name() string { return "linux-gnome-gsettings" }

type linuxState struct{ Mode, URL string }

func (a *LinuxAdapter) supported() error {
	if a.getenv == nil || !strings.Contains(strings.ToUpper(a.getenv("XDG_CURRENT_DESKTOP")), "GNOME") || a.getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return fmt.Errorf("%w: GNOME user session was not safely discoverable", ErrUnsupported)
	}
	return nil
}
func (a *LinuxAdapter) Snapshot(ctx context.Context) (json.RawMessage, error) {
	if err := a.supported(); err != nil {
		return nil, err
	}
	mode, err := a.runner.Run(ctx, gsettings, "get", gnomeProxySchema, "mode")
	if err != nil {
		return nil, err
	}
	url, err := a.runner.Run(ctx, gsettings, "get", gnomeProxySchema, "autoconfig-url")
	if err != nil {
		return nil, err
	}
	return json.Marshal(linuxState{Mode: strings.TrimSpace(string(mode)), URL: strings.TrimSpace(string(url))})
}
func (a *LinuxAdapter) Install(ctx context.Context, pac string) error {
	if err := a.supported(); err != nil {
		return err
	}
	if _, err := a.runner.Run(ctx, gsettings, "set", gnomeProxySchema, "autoconfig-url", strconv.Quote(pac)); err != nil {
		return err
	}
	_, err := a.runner.Run(ctx, gsettings, "set", gnomeProxySchema, "mode", "'auto'")
	return err
}
func (a *LinuxAdapter) Owns(ctx context.Context, pac string) (bool, error) {
	raw, err := a.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	var s linuxState
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, err
	}
	return s.Mode == "'auto'" && (s.URL == strconv.Quote(pac) || s.URL == "'"+pac+"'"), nil
}

func (a *LinuxAdapter) Matches(ctx context.Context, want json.RawMessage) (bool, error) {
	got, err := a.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	return string(got) == string(want), nil
}
func (a *LinuxAdapter) Restore(ctx context.Context, raw json.RawMessage) error {
	if err := a.supported(); err != nil {
		return err
	}
	var s linuxState
	if err := json.Unmarshal(raw, &s); err != nil || s.Mode == "" || s.URL == "" {
		return fmt.Errorf("invalid GNOME proxy snapshot")
	}
	if _, err := a.runner.Run(ctx, gsettings, "set", gnomeProxySchema, "autoconfig-url", s.URL); err != nil {
		return err
	}
	_, err := a.runner.Run(ctx, gsettings, "set", gnomeProxySchema, "mode", s.Mode)
	return err
}

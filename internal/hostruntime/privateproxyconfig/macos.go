package privateproxyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const networksetup = "/usr/sbin/networksetup"

type MacOSAdapter struct{ runner CommandRunner }

func NewMacOSAdapter(runner CommandRunner) *MacOSAdapter { return &MacOSAdapter{runner: runner} }
func (a *MacOSAdapter) Name() string                     { return "macos-networksetup" }

type macState struct {
	Services []macService `json:"services"`
}
type macService struct {
	Name, URL string
	Enabled   bool
}

func (a *MacOSAdapter) Snapshot(ctx context.Context) (json.RawMessage, error) {
	out, err := a.runner.Run(ctx, networksetup, "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var state macState
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "An asterisk") || strings.HasPrefix(name, "*") {
			continue
		}
		proxy, err := a.runner.Run(ctx, networksetup, "-getautoproxyurl", name)
		if err != nil {
			return nil, fmt.Errorf("read auto proxy for %q: %w", name, err)
		}
		service, err := parseMacProxy(name, string(proxy))
		if err != nil {
			return nil, err
		}
		state.Services = append(state.Services, service)
	}
	if len(state.Services) == 0 {
		return nil, fmt.Errorf("%w: no active macOS network services", ErrUnsupported)
	}
	return json.Marshal(state)
}

func parseMacProxy(name, output string) (macService, error) {
	s := macService{Name: name}
	seenURL, seenEnabled := false, false
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "URL":
			s.URL, seenURL = strings.TrimSpace(value), true
			if s.URL == "(null)" {
				s.URL = ""
			}
		case "Enabled":
			seenEnabled = true
			switch strings.TrimSpace(value) {
			case "Yes":
				s.Enabled = true
			case "No":
			default:
				return s, fmt.Errorf("unknown auto proxy state for %q", name)
			}
		}
	}
	if !seenURL || !seenEnabled {
		return s, fmt.Errorf("incomplete auto proxy state for %q", name)
	}
	return s, nil
}

func (a *MacOSAdapter) Install(ctx context.Context, pac string) error {
	raw, err := a.Snapshot(ctx)
	if err != nil {
		return err
	}
	var state macState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	for i, service := range state.Services {
		if _, err := a.runner.Run(ctx, networksetup, "-setautoproxyurl", service.Name, pac); err != nil {
			return a.rollback(ctx, state.Services[:i], err)
		}
		if _, err := a.runner.Run(ctx, networksetup, "-setautoproxystate", service.Name, "on"); err != nil {
			return a.rollback(ctx, state.Services[:i+1], err)
		}
	}
	return nil
}
func (a *MacOSAdapter) Owns(ctx context.Context, pac string) (bool, error) {
	raw, err := a.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	var state macState
	if err := json.Unmarshal(raw, &state); err != nil {
		return false, err
	}
	for _, service := range state.Services {
		if !service.Enabled || service.URL != pac {
			return false, nil
		}
	}
	return true, nil
}

func (a *MacOSAdapter) Matches(ctx context.Context, want json.RawMessage) (bool, error) {
	got, err := a.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	var gotState, wantState macState
	if json.Unmarshal(got, &gotState) != nil || json.Unmarshal(want, &wantState) != nil || len(gotState.Services) != len(wantState.Services) {
		return false, nil
	}
	for index := range gotState.Services {
		current, expected := gotState.Services[index], wantState.Services[index]
		if current.Name != expected.Name || current.Enabled != expected.Enabled {
			return false, nil
		}
		// macOS retains the last PAC URL after auto-proxy is disabled. The URL
		// is operationally irrelevant while disabled and must not turn a
		// completed restore into a false ownership conflict.
		if expected.Enabled && current.URL != expected.URL {
			return false, nil
		}
	}
	return true, nil
}
func (a *MacOSAdapter) Restore(ctx context.Context, raw json.RawMessage) error {
	var state macState
	if err := json.Unmarshal(raw, &state); err != nil || len(state.Services) == 0 {
		return errors.New("invalid macOS proxy snapshot")
	}
	var result error
	for _, s := range state.Services {
		result = errors.Join(result, a.restoreOne(ctx, s))
	}
	return result
}
func (a *MacOSAdapter) rollback(ctx context.Context, services []macService, cause error) error {
	result := cause
	for _, s := range services {
		result = errors.Join(result, a.restoreOne(ctx, s))
	}
	return result
}
func (a *MacOSAdapter) restoreOne(ctx context.Context, s macService) error {
	var result error
	if s.URL != "" {
		_, err := a.runner.Run(ctx, networksetup, "-setautoproxyurl", s.Name, s.URL)
		result = errors.Join(result, err)
	}
	state := "off"
	if s.Enabled {
		state = "on"
	}
	_, err := a.runner.Run(ctx, networksetup, "-setautoproxystate", s.Name, state)
	return errors.Join(result, err)
}

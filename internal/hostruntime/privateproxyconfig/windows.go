package privateproxyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// RegistryBackend must be bound to HKCU of the current interactive user. A
// service running as SYSTEM must not substitute its own HKCU or guess a profile.
type RegistryBackend interface {
	InteractiveUser(context.Context) (bool, error)
	GetAutoConfigURL(context.Context) (RegistryValue, error)
	SetAutoConfigURL(context.Context, RegistryValue) error
	BroadcastInternetSettingsChanged(context.Context) error
}

type RegistryValue struct {
	Exists bool   `json:"exists"`
	Kind   uint32 `json:"kind,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type WindowsAdapter struct{ registry RegistryBackend }

func NewWindowsAdapter(registry RegistryBackend) *WindowsAdapter {
	return &WindowsAdapter{registry: registry}
}
func (a *WindowsAdapter) Name() string { return "windows-user-wininet" }
func (a *WindowsAdapter) check(ctx context.Context) error {
	if a.registry == nil {
		return fmt.Errorf("%w: no interactive-user registry backend", ErrUnsupported)
	}
	ok, err := a.registry.InteractiveUser(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: current process is not the interactive user", ErrUnsupported)
	}
	return nil
}
func (a *WindowsAdapter) Snapshot(ctx context.Context) (json.RawMessage, error) {
	if err := a.check(ctx); err != nil {
		return nil, err
	}
	v, err := a.registry.GetAutoConfigURL(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
func (a *WindowsAdapter) Install(ctx context.Context, pac string) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	// REG_SZ is encoded by the backend; Kind 1 mirrors the Windows registry API.
	if err := a.registry.SetAutoConfigURL(ctx, RegistryValue{Exists: true, Kind: 1, Data: []byte(pac)}); err != nil {
		return err
	}
	return a.registry.BroadcastInternetSettingsChanged(ctx)
}
func (a *WindowsAdapter) Owns(ctx context.Context, pac string) (bool, error) {
	if err := a.check(ctx); err != nil {
		return false, err
	}
	v, err := a.registry.GetAutoConfigURL(ctx)
	if err != nil {
		return false, err
	}
	return v.Exists && v.Kind == 1 && string(v.Data) == pac, nil
}

func (a *WindowsAdapter) Matches(ctx context.Context, want json.RawMessage) (bool, error) {
	got, err := a.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	var g, w RegistryValue
	if json.Unmarshal(got, &g) != nil || json.Unmarshal(want, &w) != nil {
		return false, errors.New("invalid Windows proxy snapshot")
	}
	return g.Exists == w.Exists && g.Kind == w.Kind && string(g.Data) == string(w.Data), nil
}
func (a *WindowsAdapter) Restore(ctx context.Context, raw json.RawMessage) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	var v RegistryValue
	if err := json.Unmarshal(raw, &v); err != nil {
		return errors.New("invalid Windows proxy snapshot")
	}
	if err := a.registry.SetAutoConfigURL(ctx, v); err != nil {
		return err
	}
	return a.registry.BroadcastInternetSettingsChanged(ctx)
}

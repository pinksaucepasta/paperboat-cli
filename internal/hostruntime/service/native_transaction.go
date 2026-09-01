package service

import (
	"context"
	"errors"
	"os"
)

const maxNativeServiceDefinitionSize = 128 << 10

type NativeControllerStatus struct {
	Registered bool
	Enabled    bool
	Running    bool
	Ready      bool
}

// NativeLifecycleController exposes only native service-manager operations.
// Readiness must mean the manager observed the service-specific ready state,
// not merely that a process exists.
type NativeLifecycleController interface {
	Controller
	Inspect(context.Context, string) (NativeControllerStatus, error)
	Enable(context.Context, string) error
	Disable(context.Context, string) error
	Start(context.Context, string) error
	Stop(context.Context, string) error
}

type NativeTransactionalComponentConfig struct {
	Installer  *Installer
	Controller NativeLifecycleController
	// Probe optionally strengthens manager readiness with an application-level
	// bounded health check, such as the hostd authenticated local endpoint.
	Probe func(context.Context) error
}

type NativeTransactionalComponent struct {
	installer  *Installer
	controller NativeLifecycleController
	probe      func(context.Context) error
	id         string
}

func NewNativeTransactionalComponent(config NativeTransactionalComponentConfig) (*NativeTransactionalComponent, error) {
	if config.Installer == nil || config.Controller == nil || !safeLifecycleID(config.Installer.config.Kind) {
		return nil, ErrLifecycleInvalid
	}
	// Keep install/rollback and inspect/start/stop on one exact native manager
	// implementation even when a caller constructed the installer earlier.
	config.Installer.config.Controller = config.Controller
	return &NativeTransactionalComponent{installer: config.Installer, controller: config.Controller, probe: config.Probe, id: config.Installer.config.Kind}, nil
}

func (c *NativeTransactionalComponent) ID() string { return c.id }

func (c *NativeTransactionalComponent) Inspect(ctx context.Context) (NativeComponentStatus, error) {
	if c == nil || ctx == nil {
		return NativeComponentStatus{}, ErrLifecycleInvalid
	}
	state, err := c.controller.Inspect(ctx, c.installer.definitionPath)
	if err != nil {
		return NativeComponentStatus{}, err
	}
	definition, err := readNativeDefinition(c.installer.definitionPath)
	if errors.Is(err, os.ErrNotExist) {
		if state.Registered || state.Enabled || state.Running || state.Ready {
			return NativeComponentStatus{}, ErrLifecycleUncertain
		}
		return NativeComponentStatus{ID: c.id}, nil
	}
	if err != nil {
		return NativeComponentStatus{}, err
	}
	return NativeComponentStatus{
		ID: c.id, Installed: true, Enabled: state.Enabled,
		Running: state.Running, Ready: state.Ready, Definition: definition,
	}, nil
}

func (c *NativeTransactionalComponent) Install(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrLifecycleInvalid
	}
	// Keep declaration publication, enablement, and process start as separate
	// transaction phases. Installer.Install intentionally retains its legacy
	// activate-on-first-install behavior for standalone callers, while the
	// lifecycle component must be able to roll back each phase independently.
	if _, _, err := c.installer.writeDefinition(ctx); err != nil {
		return err
	}
	return c.controller.Enable(ctx, c.installer.definitionPath)
}

func (c *NativeTransactionalComponent) Start(ctx context.Context) error {
	return c.controller.Start(ctx, c.installer.definitionPath)
}

func (c *NativeTransactionalComponent) Repair(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrLifecycleInvalid
	}
	definition, err := c.installer.render()
	if err != nil {
		return err
	}
	if err := atomicWrite(c.installer.definitionPath, definition, 0o600); err != nil {
		return err
	}
	if err := c.controller.Enable(ctx, c.installer.definitionPath); err != nil {
		return err
	}
	return nil
}

func (c *NativeTransactionalComponent) Stop(ctx context.Context) error {
	return c.controller.Stop(ctx, c.installer.definitionPath)
}

func (c *NativeTransactionalComponent) Uninstall(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrLifecycleInvalid
	}
	return c.installer.Uninstall(ctx)
}

// CheckReadiness runs the component-specific application probe. Native
// service-manager state alone only proves that a process is running; the
// lifecycle transaction calls this after Start so a failed health endpoint
// triggers the same bounded rollback as any other phase failure.
func (c *NativeTransactionalComponent) CheckReadiness(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrLifecycleInvalid
	}
	if c.probe == nil {
		return nil
	}
	return c.probe(ctx)
}

func (c *NativeTransactionalComponent) Restore(ctx context.Context, status NativeComponentStatus) error {
	if c == nil || ctx == nil || status.ID != c.id || !validComponentStatus(status) {
		return ErrLifecycleInvalid
	}
	if !status.Installed {
		return c.installer.Uninstall(ctx)
	}
	if err := atomicWrite(c.installer.definitionPath, status.Definition, 0o600); err != nil {
		return err
	}
	if status.Enabled {
		if err := c.controller.Enable(ctx, c.installer.definitionPath); err != nil {
			return err
		}
	} else if err := c.controller.Disable(ctx, c.installer.definitionPath); err != nil {
		return err
	}
	if status.Running {
		return c.controller.Start(ctx, c.installer.definitionPath)
	}
	return c.controller.Stop(ctx, c.installer.definitionPath)
}

func readNativeDefinition(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxNativeServiceDefinitionSize {
		return nil, ErrLifecycleInvalid
	}
	definition, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(definition) == 0 || len(definition) > maxNativeServiceDefinitionSize {
		return nil, ErrLifecycleInvalid
	}
	return definition, nil
}

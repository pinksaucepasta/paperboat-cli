package privatepreviewproxy

import (
	"context"
	"errors"
	"sync"
)

// PACConfigurator owns only the trusted local PAC setting installed by hostd.
// Recover must restore or reconcile an interrupted prior transaction before a
// new proxy setting is installed. Implementations must never accept network
// PAC discovery or WPAD as Paperboat configuration.
type PACConfigurator interface {
	Recover(context.Context) error
	Install(context.Context, string) error
	Remove(context.Context) error
}

type AccessServiceConfig struct {
	Proxy        AccessProxyConfig
	Configurator PACConfigurator
}

// AccessService owns the local CONNECT listener and its system PAC setting as
// one hostd lifecycle. It starts the listener before publishing the PAC URL,
// and removes the PAC setting before closing the listener.
type AccessService struct {
	config AccessServiceConfig

	mu      sync.Mutex
	proxy   *AccessProxy
	running bool
}

func NewAccessService(config AccessServiceConfig) (*AccessService, error) {
	if config.Proxy.Source == nil || config.Configurator == nil {
		return nil, ErrAccessProxyInvalid
	}
	return &AccessService{config: config}, nil
}

func (s *AccessService) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrAccessProxyInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.proxy != nil {
		return ErrAccessProxyInvalid
	}
	if err := s.config.Configurator.Recover(ctx); err != nil {
		return err
	}
	proxy, err := StartAccessProxy(ctx, s.config.Proxy)
	if err != nil {
		return err
	}
	if err := s.config.Configurator.Install(ctx, proxy.PACURL); err != nil {
		return errors.Join(err, proxy.Close())
	}
	s.proxy = proxy
	s.running = true
	return nil
}

func (s *AccessService) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrAccessProxyInvalid
	}
	s.mu.Lock()
	if !s.running || s.proxy == nil {
		s.mu.Unlock()
		return nil
	}
	proxy := s.proxy
	s.proxy = nil
	s.running = false
	s.mu.Unlock()
	return errors.Join(s.config.Configurator.Remove(ctx), proxy.Close())
}

func (s *AccessService) PACURL() (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.proxy == nil {
		return "", false
	}
	return s.proxy.PACURL, true
}

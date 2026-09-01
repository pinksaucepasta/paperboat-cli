package privatepreviewproxy

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type accessConfiguratorStub struct {
	mu         sync.Mutex
	calls      []string
	recoverErr error
	installErr error
	removeErr  error
}

func (s *accessConfiguratorStub) Recover(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "recover")
	return s.recoverErr
}

func (s *accessConfiguratorStub) Install(_ context.Context, pacURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "install:"+pacURL)
	return s.installErr
}

func (s *accessConfiguratorStub) Remove(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "remove")
	return s.removeErr
}

func (s *accessConfiguratorStub) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func TestAccessServiceOwnsPACAndProxyLifecycle(t *testing.T) {
	configurator := &accessConfiguratorStub{}
	source := &accessTestSource{routes: []AccessRoute{{Hostname: "private.example.test"}}}
	service, err := NewAccessService(AccessServiceConfig{Proxy: AccessProxyConfig{Source: source}, Configurator: configurator})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pacURL, ok := service.PACURL()
	if !ok || pacURL == "" {
		t.Fatalf("PAC URL = %q, %v", pacURL, ok)
	}
	if got := configurator.snapshot(); len(got) != 2 || got[0] != "recover" || got[1] != "install:"+pacURL {
		t.Fatalf("startup calls = %v", got)
	}
	if err := service.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := configurator.snapshot(); !reflect.DeepEqual(got, []string{"recover", "install:" + pacURL, "remove"}) {
		t.Fatalf("lifecycle calls = %v", got)
	}
	if _, ok := service.PACURL(); ok {
		t.Fatal("PAC remained published after shutdown")
	}
}

func TestAccessServiceFailsClosedBeforePublishingPAC(t *testing.T) {
	recoverFailure := errors.New("recover failed")
	configurator := &accessConfiguratorStub{recoverErr: recoverFailure}
	service, err := NewAccessService(AccessServiceConfig{
		Proxy: AccessProxyConfig{Source: &accessTestSource{}}, Configurator: configurator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, recoverFailure) {
		t.Fatalf("start error = %v", err)
	}
	if got := configurator.snapshot(); !reflect.DeepEqual(got, []string{"recover"}) {
		t.Fatalf("calls = %v", got)
	}
	if _, ok := service.PACURL(); ok {
		t.Fatal("PAC published after failed recovery")
	}
}

func TestAccessServiceClosesListenerWhenPACInstallFails(t *testing.T) {
	installFailure := errors.New("install failed")
	configurator := &accessConfiguratorStub{installErr: installFailure}
	service, err := NewAccessService(AccessServiceConfig{
		Proxy: AccessProxyConfig{Source: &accessTestSource{}}, Configurator: configurator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); !errors.Is(err, installFailure) {
		t.Fatalf("start error = %v", err)
	}
	if _, ok := service.PACURL(); ok {
		t.Fatal("PAC published after failed install")
	}
	if got := configurator.snapshot(); len(got) != 2 || got[0] != "recover" || got[1] == "" {
		t.Fatalf("calls = %v", got)
	}
}

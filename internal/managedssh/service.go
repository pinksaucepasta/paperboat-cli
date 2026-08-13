package managedssh

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type AgentServiceConfig struct {
	RuntimeDirectory     string
	InheritedAgentSocket string
	Signer               ssh.Signer
	MaxConnections       int
	IdleTimeout          time.Duration
	DelegateTimeout      time.Duration
}

type AgentService struct {
	socket   string
	cancel   context.CancelFunc
	done     chan error
	delegate *DelegatedAgent
	once     sync.Once
	err      error
}

func StartAgentService(parent context.Context, config AgentServiceConfig) (*AgentService, error) {
	if parent == nil || !filepath.IsAbs(config.RuntimeDirectory) || config.Signer == nil || config.MaxConnections <= 0 || config.IdleTimeout <= 0 {
		return nil, ErrAgentDenied
	}
	managed, err := NewAgent(config.Signer)
	if err != nil {
		return nil, err
	}
	socket := filepath.Join(filepath.Clean(config.RuntimeDirectory), "paperboat-ssh-agent.sock")
	var delegate *DelegatedAgent
	if config.InheritedAgentSocket != "" {
		delegate, err = DialOwnerAgent(config.InheritedAgentSocket, socket, config.DelegateTimeout)
		if err != nil {
			return nil, err
		}
	}
	aggregate, err := NewAggregate(managed, delegate)
	if err != nil {
		if delegate != nil {
			_ = delegate.Close()
		}
		return nil, err
	}
	listener, err := ListenOwnerSocket(socket)
	if err != nil {
		if delegate != nil {
			_ = delegate.Close()
		}
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	service := &AgentService{socket: socket, cancel: cancel, done: make(chan error, 1), delegate: delegate}
	go func() {
		service.done <- (Server{Agent: aggregate, MaxConnections: config.MaxConnections, IdleTimeout: config.IdleTimeout}).Serve(ctx, listener)
	}()
	return service, nil
}

func (s *AgentService) Socket() string {
	if s == nil {
		return ""
	}
	return s.socket
}

func (s *AgentService) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.cancel()
		serveErr := <-s.done
		var delegateErr error
		if s.delegate != nil {
			delegateErr = s.delegate.Close()
		}
		s.err = errors.Join(serveErr, delegateErr)
	})
	return s.err
}

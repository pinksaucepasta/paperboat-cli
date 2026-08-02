package serve

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const DefaultDrainTimeout = 10 * time.Second

type Server struct {
	listener net.Listener
	http     *http.Server
	done     chan error
	closer   io.Closer
	close    sync.Once
}

func Start(handler http.Handler) (*Server, error) {
	if handler == nil {
		return nil, ErrInvalidSource
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if closer, ok := handler.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	server := &Server{listener: listener, http: &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}, done: make(chan error, 1)}
	server.closer, _ = handler.(io.Closer)
	go func() {
		err := server.http.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		server.done <- err
		close(server.done)
	}()
	return server, nil
}

func (s *Server) Port() uint16 {
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}

func (s *Server) Done() <-chan error { return s.done }

func (s *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), DefaultDrainTimeout)
		defer cancel()
	}
	shutdownErr := s.http.Shutdown(ctx)
	var closeErr error
	s.close.Do(func() {
		if s.closer != nil {
			closeErr = s.closer.Close()
		}
	})
	return errors.Join(shutdownErr, closeErr)
}

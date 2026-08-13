package privatepreviewproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var ErrInvalid = errors.New("invalid private preview proxy configuration")

type Dial func(context.Context) (io.ReadWriteCloser, error)

type Config struct {
	ListenPort         uint16
	Dial               Dial
	MaximumConnections int
}

type Proxy struct {
	URL      string
	listener net.Listener
	dial     Dial
	permits  chan struct{}
	cancel   context.CancelFunc
	done     chan error
	mu       sync.Mutex
	active   map[io.Closer]struct{}
	once     sync.Once
}

func Start(ctx context.Context, config Config) (*Proxy, error) {
	if config.MaximumConnections == 0 {
		config.MaximumConnections = 128
	}
	if ctx == nil || config.Dial == nil || config.MaximumConnections < 1 || config.MaximumConnections > 4096 {
		return nil, ErrInvalid
	}
	// This proves the selected peer path and remote loopback target before a URL
	// can be exposed. It is consumed by the first accepted browser connection.
	preflight, err := config.Dial(ctx)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", config.ListenPort))
	if err != nil {
		return nil, errors.Join(err, preflight.Close())
	}
	runCtx, cancel := context.WithCancel(ctx)
	proxy := &Proxy{URL: "http://" + listener.Addr().String(), listener: listener, dial: config.Dial, permits: make(chan struct{}, config.MaximumConnections), cancel: cancel, done: make(chan error, 1), active: make(map[io.Closer]struct{})}
	proxy.track(preflight, true)
	go proxy.run(runCtx, preflight)
	go func() {
		<-runCtx.Done()
		_ = proxy.Close()
	}()
	return proxy, nil
}

func (p *Proxy) Wait() error {
	if p == nil || p.done == nil {
		return ErrInvalid
	}
	return <-p.done
}

func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	var result error
	p.once.Do(func() {
		p.cancel()
		result = p.listener.Close()
		p.mu.Lock()
		active := make([]io.Closer, 0, len(p.active))
		for connection := range p.active {
			active = append(active, connection)
		}
		p.mu.Unlock()
		for _, connection := range active {
			result = errors.Join(result, connection.Close())
		}
	})
	return result
}

func (p *Proxy) run(ctx context.Context, preflight io.ReadWriteCloser) {
	var workers sync.WaitGroup
	var result error
	defer func() {
		_ = p.Close()
		workers.Wait()
		if result == nil {
			result = contextCause(ctx)
		}
		p.done <- result
		close(p.done)
	}()
	first := preflight
	for {
		local, err := p.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			result = err
			return
		}
		select {
		case p.permits <- struct{}{}:
		case <-ctx.Done():
			_ = local.Close()
			return
		}
		remote := first
		first = nil
		if remote == nil {
			remote, err = p.dial(ctx)
		}
		if err != nil {
			_ = local.Close()
			<-p.permits
			continue
		}
		p.track(local, true)
		p.track(remote, true)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-p.permits }()
			_ = copyBoth(local, remote)
			p.track(local, false)
			p.track(remote, false)
			_ = local.Close()
			_ = remote.Close()
		}()
	}
}

func (p *Proxy) track(connection io.Closer, add bool) {
	p.mu.Lock()
	if add {
		p.active[connection] = struct{}{}
	} else {
		delete(p.active, connection)
	}
	p.mu.Unlock()
}

func copyBoth(local net.Conn, remote io.ReadWriteCloser) error {
	results := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, local)
		if closer, ok := remote.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		} else {
			err = errors.Join(err, remote.Close())
		}
		results <- err
	}()
	go func() {
		_, err := io.Copy(local, remote)
		if closer, ok := local.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		} else {
			err = errors.Join(err, local.Close())
		}
		results <- err
	}()
	return errors.Join(<-results, <-results)
}

func contextCause(ctx context.Context) error {
	err := context.Cause(ctx)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

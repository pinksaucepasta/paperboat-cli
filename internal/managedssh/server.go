package managedssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

const MaxAgentRequestBytes = 128 << 10

type Server struct {
	Agent          agent.Agent
	MaxConnections int
	IdleTimeout    time.Duration
}

func (s Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil || s.Agent == nil || s.MaxConnections <= 0 || s.MaxConnections > 64 || s.IdleTimeout <= 0 || s.IdleTimeout > 10*time.Minute {
		return ErrAgentDenied
	}
	ctx, cancel := context.WithCancel(ctx)
	connections := make(chan struct{}, s.MaxConnections)
	var group sync.WaitGroup
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	defer group.Wait()
	defer cancel()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
			group.Add(1)
			go func() {
				defer group.Done()
				defer func() { <-connections }()
				defer connection.Close()
				_ = s.serveConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s Server) serveConnection(ctx context.Context, connection net.Conn) error {
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var header [4]byte
	for {
		if err := connection.SetDeadline(time.Now().Add(s.IdleTimeout)); err != nil {
			return err
		}
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > MaxAgentRequestBytes {
			return ErrAgentRequestTooLarge
		}
		request := make([]byte, int(length)+len(header))
		copy(request, header[:])
		if _, err := io.ReadFull(connection, request[len(header):]); err != nil {
			return err
		}
		var response bytes.Buffer
		err := agent.ServeAgent(s.Agent, &singleRequest{reader: bytes.NewReader(request), writer: &response})
		if !errors.Is(err, io.EOF) {
			return err
		}
		if response.Len() == 0 || response.Len() > MaxAgentRequestBytes {
			return ErrAgentRequestTooLarge
		}
		if _, err := connection.Write(response.Bytes()); err != nil {
			return err
		}
	}
}

type singleRequest struct {
	reader *bytes.Reader
	writer *bytes.Buffer
}

func (r *singleRequest) Read(value []byte) (int, error)  { return r.reader.Read(value) }
func (r *singleRequest) Write(value []byte) (int, error) { return r.writer.Write(value) }

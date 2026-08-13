package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

type sshRequest struct {
	OperationID string `json:"operation_id"`
	Generation  uint64 `json:"generation"`
}

type sshStreamRegistry struct {
	mu      sync.RWMutex
	streams map[string]*sshOutputStream
}

func (d *Dispatcher) sshRequest(payload json.RawMessage) operation.Outcome {
	if d.config.SSH == nil {
		return failure("capability_required")
	}
	var request sshRequest
	if decodeStrict(payload, &request) != nil || request.OperationID == "" || request.Generation == 0 {
		return failure("invalid_request")
	}
	target, ok := d.config.SSH.Target()
	if !ok || target.Generation != request.Generation {
		return failure("ssh_target_not_ready")
	}
	return result(struct {
		Generation uint64 `json:"generation"`
	}{Generation: request.Generation})
}

func (d *Dispatcher) openSSHStream(ctx context.Context, authorization Authorization, payload json.RawMessage, outcome operation.Outcome) (OutputStream, bool, error) {
	if d.config.SSH == nil || outcome.ErrorCode != "" {
		return nil, false, nil
	}
	var request sshRequest
	if decodeStrict(payload, &request) != nil || request.OperationID == "" || request.Generation == 0 || authorization.ClientID == "" {
		return nil, false, nil
	}
	stream := newSSHOutputStream(request.OperationID, func() { d.ssh.remove(request.OperationID) })
	if !d.ssh.add(request.OperationID, stream) {
		_ = stream.Close()
		return nil, false, errors.New("SSH operation is already attached")
	}
	go func() {
		_, err := d.config.SSH.Serve(ctx, request.Generation, stream.host)
		stream.finish(err)
	}()
	return stream, true, nil
}

func (d *Dispatcher) HandleSSHInput(_ context.Context, authorization Authorization, operationID string, data []byte) error {
	if authorization.ClientID == "" || operationID == "" || len(data) == 0 {
		return errors.New("invalid SSH input")
	}
	stream := d.ssh.get(operationID)
	if stream == nil {
		return errors.New("SSH stream is unavailable")
	}
	_, err := stream.input.Write(data)
	return err
}

func (d *Dispatcher) HandleSSHEOF(_ context.Context, authorization Authorization, operationID string) error {
	if authorization.ClientID == "" || operationID == "" {
		return errors.New("invalid SSH EOF")
	}
	stream := d.ssh.get(operationID)
	if stream == nil {
		return errors.New("SSH stream is unavailable")
	}
	return stream.closeWrite()
}

func (r *sshStreamRegistry) add(operationID string, stream *sshOutputStream) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams == nil {
		r.streams = make(map[string]*sshOutputStream)
	}
	if r.streams[operationID] != nil {
		return false
	}
	r.streams[operationID] = stream
	return true
}

func (r *sshStreamRegistry) get(operationID string) *sshOutputStream {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streams[operationID]
}

func (r *sshStreamRegistry) remove(operationID string) {
	r.mu.Lock()
	delete(r.streams, operationID)
	r.mu.Unlock()
}

type sshDuplex struct {
	input  *io.PipeReader
	output *io.PipeWriter
	once   sync.Once
}

func (s *sshDuplex) Read(value []byte) (int, error)  { return s.input.Read(value) }
func (s *sshDuplex) Write(value []byte) (int, error) { return s.output.Write(value) }
func (s *sshDuplex) Close() error {
	var err error
	s.once.Do(func() { err = errors.Join(s.input.Close(), s.output.Close()) })
	return err
}

type sshOutputStream struct {
	operationID string
	host        *sshDuplex
	input       *io.PipeWriter
	output      *io.PipeReader
	done        chan error
	remove      func()
	sequence    uint64
	writeOnce   sync.Once
	finishOnce  sync.Once
	closeOnce   sync.Once
}

func newSSHOutputStream(operationID string, remove func()) *sshOutputStream {
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	return &sshOutputStream{operationID: operationID, host: &sshDuplex{input: inputReader, output: outputWriter}, input: inputWriter, output: outputReader, done: make(chan error, 1), remove: remove, sequence: 1}
}

func (s *sshOutputStream) Next(ctx context.Context) (protocol.BinaryFrame, error) {
	buffer := make([]byte, 32<<10)
	type readResult struct {
		count int
		err   error
	}
	result := make(chan readResult, 1)
	go func() { count, err := s.output.Read(buffer); result <- readResult{count: count, err: err} }()
	select {
	case <-ctx.Done():
		return protocol.BinaryFrame{}, ctx.Err()
	case read := <-result:
		if read.count > 0 {
			frame := protocol.BinaryFrame{Channel: protocol.Stdout, StartSequence: s.sequence, Data: buffer[:read.count]}
			s.sequence += uint64(read.count)
			return frame, nil
		}
		bridgeErr := <-s.done
		if bridgeErr != nil && !errors.Is(bridgeErr, context.Canceled) {
			return protocol.BinaryFrame{}, &StreamError{Code: "ssh_target_not_ready"}
		}
		return protocol.BinaryFrame{}, &StreamEnd{Payload: json.RawMessage(`{"state":"closed"}`)}
	}
}

func (s *sshOutputStream) closeWrite() error {
	var err error
	s.writeOnce.Do(func() { err = s.input.Close() })
	return err
}

func (s *sshOutputStream) finish(err error) {
	s.finishOnce.Do(func() {
		_ = s.host.Close()
		s.done <- err
		close(s.done)
	})
}

func (s *sshOutputStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.remove != nil {
			s.remove()
		}
		err = errors.Join(s.input.Close(), s.output.Close(), s.host.Close())
	})
	return err
}

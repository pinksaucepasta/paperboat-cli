package peerquic

import (
	"context"
	"io"
)

// OpenCandidateControl opens the reserved direct physical-candidate stream.
func (s *Session) OpenCandidateControl(ctx context.Context, payload []byte) (io.ReadWriteCloser, error) {
	if s == nil || s.Connection == nil || ctx == nil {
		return nil, ErrStreamRouterProtocol
	}
	stream, err := s.Connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write(candidateControlMagic[:]); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if _, err := stream.Write(payload); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

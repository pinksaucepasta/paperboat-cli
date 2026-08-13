package tunnel

import (
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

type boundNativeStream struct {
	nativeStream
	binding [32]byte
	once    sync.Once
	err     error
}

type authorizedNativeStream struct{ nativeStream }

func (s *boundNativeStream) SetDeadline(deadline time.Time) error {
	stream, ok := s.nativeStream.(interface{ SetDeadline(time.Time) error })
	if !ok {
		return peerquic.ErrRecord
	}
	return stream.SetDeadline(deadline)
}

func (s *boundNativeStream) SetReadDeadline(deadline time.Time) error {
	stream, ok := s.nativeStream.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return peerquic.ErrRecord
	}
	return stream.SetReadDeadline(deadline)
}

func (s *boundNativeStream) SetWriteDeadline(deadline time.Time) error {
	stream, ok := s.nativeStream.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return peerquic.ErrRecord
	}
	return stream.SetWriteDeadline(deadline)
}

// quic.Stream.Close closes only the send direction. Relay-backed native
// streams expose CloseWrite directly through their secure connection wrapper.
func (s *boundNativeStream) CloseWrite() error {
	if stream, ok := s.nativeStream.(interface{ CloseWrite() error }); ok {
		return stream.CloseWrite()
	}
	return s.nativeStream.Close()
}

func (s *authorizedNativeStream) CloseWrite() error { return s.nativeStream.Close() }

func (s *boundNativeStream) WriteFirst(payload []byte) error {
	if s == nil || s.nativeStream == nil {
		return peerquic.ErrRecord
	}
	written := false
	s.once.Do(func() {
		written = true
		record, err := peerquic.SealFirstRecord(s.binding, payload)
		if err != nil {
			s.err = err
			return
		}
		for len(record) > 0 {
			count, writeErr := s.nativeStream.Write(record)
			if writeErr != nil {
				s.err = writeErr
				return
			}
			if count == 0 {
				s.err = errors.New("peer QUIC first record made no progress")
				return
			}
			record = record[count:]
		}
	})
	if !written && s.err == nil {
		return peerquic.ErrRecord
	}
	return s.err
}

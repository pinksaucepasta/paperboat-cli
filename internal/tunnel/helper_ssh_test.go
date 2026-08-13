package tunnel

import (
	"bytes"
	"io"
	"testing"
)

type opaqueSSHStream struct {
	reader      *bytes.Reader
	written     bytes.Buffer
	halfClosed  bool
	fullyClosed bool
}

func (s *opaqueSSHStream) Read(value []byte) (int, error)  { return s.reader.Read(value) }
func (s *opaqueSSHStream) Write(value []byte) (int, error) { return s.written.Write(value) }
func (s *opaqueSSHStream) CloseWrite() error               { s.halfClosed = true; return nil }
func (s *opaqueSSHStream) Close() error                    { s.fullyClosed = true; return nil }

func TestSSHStreamConnPreservesOpaqueBytesAndHalfClose(t *testing.T) {
	fromHost := []byte{0xff, 0x00, 0x7f, 0x80, '\r', '\n'}
	toHost := []byte{0x00, 0x01, 0xfe, 0xff, '\n', 0x00}
	stream := &opaqueSSHStream{reader: bytes.NewReader(fromHost)}
	connection := &sshStreamConn{ReadWriteCloser: stream}

	read, err := io.ReadAll(connection)
	if err != nil || !bytes.Equal(read, fromHost) {
		t.Fatalf("read=%x err=%v", read, err)
	}
	if count, err := connection.Write(toHost); err != nil || count != len(toHost) {
		t.Fatalf("write count=%d err=%v", count, err)
	}
	if !bytes.Equal(stream.written.Bytes(), toHost) {
		t.Fatalf("written=%x want=%x", stream.written.Bytes(), toHost)
	}
	if err := connection.CloseWrite(); err != nil || !stream.halfClosed || stream.fullyClosed {
		t.Fatalf("close-write err=%v half=%t closed=%t", err, stream.halfClosed, stream.fullyClosed)
	}
	if err := connection.Close(); err != nil || !stream.fullyClosed {
		t.Fatalf("close err=%v closed=%t", err, stream.fullyClosed)
	}
}

type sshStreamWithoutHalfClose struct{ bytes.Buffer }

func (*sshStreamWithoutHalfClose) Close() error { return nil }

func TestSSHStreamConnRequiresTransportHalfClose(t *testing.T) {
	connection := &sshStreamConn{ReadWriteCloser: &sshStreamWithoutHalfClose{}}
	if err := connection.CloseWrite(); err != ErrInputEOFUnsupported {
		t.Fatalf("close-write err=%v", err)
	}
}

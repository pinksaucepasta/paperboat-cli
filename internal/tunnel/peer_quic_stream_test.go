package tunnel

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

func TestBoundNativeStreamSealsFirstWriteExactlyOnce(t *testing.T) {
	t.Parallel()
	stream := &partialNativeStream{limit: 3}
	var binding [32]byte
	binding[0] = 7
	bound := &boundNativeStream{nativeStream: stream, binding: binding}
	if err := bound.WriteFirst([]byte("native-preface")); err != nil {
		t.Fatal(err)
	}
	payload, err := peerquic.ReadFirstRecord(bytes.NewReader(stream.Bytes()), binding)
	if err != nil || string(payload) != "native-preface" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	if err := bound.WriteFirst([]byte("second")); err == nil {
		t.Fatal("accepted a second bound first record")
	}
}

func TestBoundNativeStreamMapsCloseWriteToQUICSendClose(t *testing.T) {
	stream := &partialNativeStream{limit: 3}
	bound := &boundNativeStream{nativeStream: stream}
	if err := bound.CloseWrite(); err != nil || !stream.closed {
		t.Fatalf("close-write err=%v closed=%t", err, stream.closed)
	}
}

func TestAuthorizedNativeStreamMapsCloseWriteToQUICSendClose(t *testing.T) {
	stream := &partialNativeStream{limit: 3}
	authorized := &authorizedNativeStream{nativeStream: stream}
	if err := authorized.CloseWrite(); err != nil || !stream.closed {
		t.Fatalf("close-write err=%v closed=%t", err, stream.closed)
	}
}

type partialNativeStream struct {
	bytes.Buffer
	limit  int
	closed bool
}

func (s *partialNativeStream) Write(payload []byte) (int, error) {
	if len(payload) > s.limit {
		payload = payload[:s.limit]
	}
	return s.Buffer.Write(payload)
}
func (*partialNativeStream) Read([]byte) (int, error)         { return 0, io.EOF }
func (s *partialNativeStream) Close() error                   { s.closed = true; return nil }
func (*partialNativeStream) SetWriteDeadline(time.Time) error { return nil }

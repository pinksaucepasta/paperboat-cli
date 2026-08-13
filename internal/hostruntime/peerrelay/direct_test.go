package peerrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/directpath"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"
)

func TestDirectFailureFallbackRequiresExplicitReachabilityClass(t *testing.T) {
	t.Parallel()
	if !directFailureAllowsFallback(context.Background(), errors.Join(directpath.ErrReachability, errors.New("ICE checklist failed"))) {
		t.Fatal("explicit reachability failure was not fallback eligible")
	}
	if directFailureAllowsFallback(context.Background(), errors.New("unknown direct failure")) {
		t.Fatal("unknown direct failure became fallback eligible")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if directFailureAllowsFallback(canceled, directpath.ErrReachability) {
		t.Fatal("canceled owner became fallback eligible")
	}
}

func TestBoundResponderConnValidatesExporterBeforePublishingBytes(t *testing.T) {
	t.Parallel()
	var binding [32]byte
	binding[0] = 5
	record, err := peerquic.SealFirstRecord(binding, []byte("native-preface"))
	if err != nil {
		t.Fatal(err)
	}
	stream := &deadlineBuffer{reader: bytes.NewReader(record)}
	connection, err := newBoundResponderConn(context.Background(), stream, binding, "machine_01", "cli_01")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(connection)
	if err != nil || string(payload) != "native-preface" || connection.LocalAddr().String() != "machine_01" || connection.RemoteAddr().String() != "cli_01" {
		t.Fatalf("payload=%q local=%s remote=%s err=%v", payload, connection.LocalAddr(), connection.RemoteAddr(), err)
	}
	wrong := binding
	wrong[0]++
	if _, err := newBoundResponderConn(context.Background(), &deadlineBuffer{reader: bytes.NewReader(record)}, wrong, "machine_01", "cli_01"); err == nil {
		t.Fatal("accepted the wrong exporter binding")
	}
}

type deadlineBuffer struct {
	reader *bytes.Reader
	bytes.Buffer
}

func (s *deadlineBuffer) Read(target []byte) (int, error) { return s.reader.Read(target) }
func (*deadlineBuffer) Close() error                      { return nil }
func (*deadlineBuffer) SetDeadline(time.Time) error       { return nil }
func (*deadlineBuffer) SetReadDeadline(time.Time) error   { return nil }
func (*deadlineBuffer) SetWriteDeadline(time.Time) error  { return nil }

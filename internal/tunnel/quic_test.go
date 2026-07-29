package tunnel

import (
	"bytes"
	"io"
	"testing"

	"github.com/pinksaucepasta/paperboat-cli/internal/resolver"
)

type oneByteReader struct{ data []byte }

type firstWriteRecorder struct{ sizes []int }

func (w *firstWriteRecorder) Write(p []byte) (int, error) {
	w.sizes = append(w.sizes, len(p))
	return len(p), nil
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestNativeRecordFragmentationPreservesBoundaries(t *testing.T) {
	var encoded bytes.Buffer
	if err := writeNativeRecord(&encoded, nativeStructured, []byte("control"), true); err != nil {
		t.Fatal(err)
	}
	if err := writeNativeRecord(&encoded, nativeBinary, []byte("binary"), true); err != nil {
		t.Fatal(err)
	}
	reader := &oneByteReader{data: encoded.Bytes()}
	for _, want := range []struct {
		kind byte
		data string
	}{{nativeStructured, "control"}, {nativeBinary, "binary"}} {
		kind, data, err := readNativeRecord(reader, true)
		if err != nil || kind != want.kind || string(data) != want.data {
			t.Fatalf("kind=%d data=%q err=%v", kind, data, err)
		}
	}
}

func TestNativeRecordIsPresentedToWriterAsOneCompleteBuffer(t *testing.T) {
	writer := &firstWriteRecorder{}
	if err := writeNativeRecord(writer, nativeBinary, []byte("payload"), true); err != nil {
		t.Fatal(err)
	}
	if len(writer.sizes) != 1 || writer.sizes[0] != 5+len("payload") {
		t.Fatalf("write sizes = %v", writer.sizes)
	}
}

func TestNativeEndpointRequiresExplicitQUICAndBearer(t *testing.T) {
	target := &resolver.TerminalTarget{QUICEndpoint: "quic://edge.example.test:443", Auth: resolver.AuthTarget{Method: "bearer", Token: "token"}}
	address, name, err := nativeEndpoint(target)
	if err != nil || address != "edge.example.test:443" || name != "edge.example.test" {
		t.Fatalf("address=%q name=%q err=%v", address, name, err)
	}
	for _, endpoint := range []string{"https://edge.example.test", "quic://edge.example.test/path", "quic://user@edge.example.test"} {
		target.QUICEndpoint = endpoint
		if _, _, err := nativeEndpoint(target); err == nil {
			t.Fatalf("accepted %q", endpoint)
		}
	}
}

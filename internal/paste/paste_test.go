package paste

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pujan-modha/paperboat-cli/internal/upload"
)

// fixedUploader returns a constant VM path.
type fixedUploader struct{ vmPath string }

func (u fixedUploader) Upload(_ context.Context, _ upload.Image) (string, error) {
	return u.vmPath, nil
}

// failUploader always errors, exercising fail-open.
type failUploader struct{}

func (failUploader) Upload(_ context.Context, _ upload.Image) (string, error) {
	return "", errors.New("boom")
}

func defaultLimits() upload.Limits {
	return upload.Limits{
		MaxImageBytes:       10 << 20,
		MaxDataURLChars:     14_000_000,
		MaxAttachments:      8,
		AllowedMimePrefixes: []string{"image/"},
	}
}

func wrap(body string) string {
	return "\x1b[200~" + body + "\x1b[201~"
}

// writeInChunks feeds s to the interceptor split at each chunk boundary.
func writeInChunks(t *testing.T, i *Interceptor, s string, chunk int) {
	t.Helper()
	for off := 0; off < len(s); off += chunk {
		end := off + chunk
		if end > len(s) {
			end = len(s)
		}
		if _, err := i.Write([]byte(s[off:end])); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := i.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func makeImage(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	// Minimal 1x1 PNG header bytes are enough; PrepareImage keys off extension.
	if err := os.WriteFile(p, []byte("\x89PNG\r\n\x1a\n-fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNonPasteBytesPassThrough(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	in := "hello world\nno paste here"
	writeInChunks(t, i, in, 3)
	if dest.String() != in {
		t.Fatalf("got %q want %q", dest.String(), in)
	}
}

func TestNonImagePasteUntouched(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	in := wrap("just some pasted text")
	writeInChunks(t, i, in, 4)
	if dest.String() != in {
		t.Fatalf("got %q want %q", dest.String(), in)
	}
}

func TestImagePasteRewritten(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "shot.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/attach/shot.png"}, defaultLimits())
	writeInChunks(t, i, wrap(img), 5)
	want := wrap("/vm/attach/shot.png")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestImagePasteSplitAcrossWrites(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "a.png")
	for _, chunk := range []int{1, 2, 7} {
		var dest bytes.Buffer
		i := New(&dest, fixedUploader{"/vm/a.png"}, defaultLimits())
		writeInChunks(t, i, wrap(img), chunk)
		if got, want := dest.String(), wrap("/vm/a.png"); got != want {
			t.Fatalf("chunk=%d got %q want %q", chunk, got, want)
		}
	}
}

func TestUploadFailureFailsOpen(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "b.png")
	var dest, notice bytes.Buffer
	i := New(&dest, failUploader{}, defaultLimits(), WithNotifier(&notice))
	writeInChunks(t, i, wrap(img), 6)
	if got := dest.String(); got != wrap(img) {
		t.Fatalf("fail-open: got %q want original %q", got, wrap(img))
	}
	if !strings.Contains(notice.String(), "upload failed") {
		t.Fatalf("expected a visible notice, got %q", notice.String())
	}
}

func TestAdjacentPastes(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "c.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/c.png"}, defaultLimits())
	in := "x" + wrap(img) + "y" + wrap("plain") + "z"
	writeInChunks(t, i, in, 3)
	want := "x" + wrap("/vm/c.png") + "y" + wrap("plain") + "z"
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestMultipleImageLines(t *testing.T) {
	dir := t.TempDir()
	a := makeImage(t, dir, "one.png")
	b := makeImage(t, dir, "two.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	writeInChunks(t, i, wrap(a+"\n"+b), 5)
	want := wrap("/vm/x.png\n/vm/x.png")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestPartialStartMarkerHeldThenFlushed(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	// A lone ESC[ that never becomes a paste must eventually pass through.
	if _, err := i.Write([]byte("ab\x1b[")); err != nil {
		t.Fatal(err)
	}
	// Not a paste start; a normal escape sequence follows.
	if _, err := i.Write([]byte("2J")); err != nil {
		t.Fatal(err)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "ab\x1b[2J" {
		t.Fatalf("got %q want %q", got, "ab\x1b[2J")
	}
}

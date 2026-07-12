package paste

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
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

type blockingUploader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type uncertainWriter struct {
	mu        sync.Mutex
	uncertain bool
	discarded int
	buf       bytes.Buffer
}

type fatalWriter struct{ err error }

func (w fatalWriter) Write([]byte) (int, error) { return 0, w.err }

func (w *uncertainWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.uncertain {
		w.uncertain = false
		return 0, tunnel.ErrWriteUncertain
	}
	return w.buf.Write(p)
}
func (w *uncertainWriter) Discard()       { w.mu.Lock(); w.discarded++; w.mu.Unlock() }
func (w *uncertainWriter) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.String() }

func (u *blockingUploader) Upload(ctx context.Context, _ upload.Image) (string, error) {
	u.once.Do(func() { close(u.started) })
	select {
	case <-u.release:
		return "/vm/slow.png", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
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

func TestImagePastePreservesWhitespaceAndQuotes(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "quoted image.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/quoted.png"}, defaultLimits())
	writeInChunks(t, i, wrap("  \""+img+"\"\t"), 4)
	if got, want := dest.String(), wrap("  \"/vm/quoted.png\"\t"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFileURLImagePaste(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "url image.png")
	fileURL := "file://" + strings.ReplaceAll(img, " ", "%20")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/url.png"}, defaultLimits())
	writeInChunks(t, i, wrap(fileURL), 3)
	if got, want := dest.String(), wrap("/vm/url.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestTempFilePatterns(t *testing.T) {
	dir := t.TempDir()
	allowed := makeImage(t, dir, "terminal-paste-123.png")
	rejected := makeImage(t, dir, "manual.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/allowed.png"}, defaultLimits(),
		WithWatchDirs([]string{dir}), WithTempFilePatterns([]string{"terminal-paste-*.png"}))
	writeInChunks(t, i, wrap(allowed)+wrap(rejected), 5)
	if got, want := dest.String(), wrap("/vm/allowed.png")+wrap(rejected); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWatchDirsRejectTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	watched := filepath.Join(root, "watched")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(watched, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideImage := makeImage(t, outside, "outside.png")
	link := filepath.Join(watched, "link.png")
	if err := os.Symlink(outsideImage, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/escape.png"}, defaultLimits(), WithWatchDirs([]string{watched}))
	writeInChunks(t, i, wrap(filepath.Join(watched, "..", "outside", "outside.png"))+wrap(link), 3)
	want := wrap(filepath.Join(watched, "..", "outside", "outside.png")) + wrap(link)
	if got := dest.String(); got != want {
		t.Fatalf("watch directory escape was rewritten: got %q want %q", got, want)
	}
}

func TestPolicyUpdateChangesUploaderForSubsequentPastes(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "shot.png")
	var dest bytes.Buffer
	policy := NewPolicy(fixedUploader{"/vm/old.png"}, defaultLimits())
	i := NewWithPolicy(&dest, policy)
	writeInChunks(t, i, wrap(img), 8)
	policy.Update(fixedUploader{"/vm/new.png"}, defaultLimits())
	dest.Reset()
	i = NewWithPolicy(&dest, policy)
	writeInChunks(t, i, wrap(img), 8)
	if got := dest.String(); got != wrap("/vm/new.png") {
		t.Fatalf("got %q", got)
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

func TestSlowUploadDoesNotBlockInitialWriteAndPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "slow.png")
	var dest bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits())

	writeDone := make(chan error, 1)
	go func() {
		_, err := i.Write([]byte(wrap(img) + "after"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write blocked on the upload")
	}
	select {
	case <-uploader.started:
	case <-time.After(time.Second):
		t.Fatal("upload did not start")
	}
	if got := dest.String(); got != "" {
		t.Fatalf("subsequent input overtook paste: %q", got)
	}
	close(uploader.release)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := dest.String(), wrap("/vm/slow.png")+"after"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAbortCancelsUpload(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "cancel.png")
	var dest bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits())
	if _, err := i.Write([]byte(wrap(img))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploader.started:
	case <-time.After(time.Second):
		t.Fatal("upload did not start")
	}
	i.Abort()
	if err := i.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close error = %v, want context cancellation", err)
	}
}

func TestUncertainDestinationWriteIsRecoveredByWorker(t *testing.T) {
	dest := &uncertainWriter{uncertain: true}
	i := New(dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	if _, err := i.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "second" {
		t.Fatalf("got %q, want recovered subsequent input", got)
	}
	if dest.discarded == 0 {
		t.Fatal("destination discard hook was not called")
	}
}

func TestFatalDestinationWriteIsReportedAsynchronously(t *testing.T) {
	want := errors.New("fatal destination")
	i := New(fatalWriter{err: want}, fixedUploader{"/vm/x.png"}, defaultLimits())
	if _, err := i.Write([]byte("input")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-i.Errors():
		if !errors.Is(got, want) {
			t.Fatalf("error = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("fatal worker error was not reported")
	}
	if err := i.Close(); !errors.Is(err, want) {
		t.Fatalf("Close error = %v, want %v", err, want)
	}
	if _, err := i.Write([]byte("later")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write after Close = %v, want closed pipe", err)
	}
}

func TestSlowUploadAppliesBoundedBackpressure(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "bounded.png")
	var dest, notice bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits(), WithMaxQueuedBytes(8), WithNotifier(&notice))
	if _, err := i.Write([]byte(wrap(img))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploader.started:
	case <-time.After(time.Second):
		t.Fatal("upload did not start")
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := i.Write([]byte("sixteen-bytes!!!"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("queued write bypassed backpressure: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if !strings.Contains(notice.String(), "local input queue is full") {
		t.Fatalf("missing backpressure notice: %q", notice.String())
	}
	close(uploader.release)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued write did not resume")
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := dest.String(), wrap("/vm/slow.png")+"sixteen-bytes!!!"; got != want {
		t.Fatalf("got %q want %q", got, want)
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

func TestMultipleImageLinesPreserveBlankLines(t *testing.T) {
	dir := t.TempDir()
	a := makeImage(t, dir, "one.png")
	b := makeImage(t, dir, "two.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits())
	writeInChunks(t, i, wrap(a+"\n\n"+b+"\n"), 5)
	want := wrap("/vm/x.png\n\n/vm/x.png\n")
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

func FuzzBracketedPasteStreamPreservesUnknownInput(f *testing.F) {
	f.Add([]byte("plain text"), uint8(1))
	f.Add([]byte(wrap("not an image")), uint8(3))
	f.Add([]byte("x\x1b[200~partial"), uint8(7))
	f.Fuzz(func(t *testing.T, input []byte, chunkByte uint8) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		chunk := int(chunkByte)%64 + 1
		var dest bytes.Buffer
		i := New(&dest, fixedUploader{"/vm/fuzz.png"}, defaultLimits())
		writeInChunks(t, i, string(input), chunk)
		if !bytes.Equal(dest.Bytes(), input) {
			t.Fatalf("stream changed: got %q want %q", dest.Bytes(), input)
		}
	})
}

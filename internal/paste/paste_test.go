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

	transfer "github.com/pinksaucepasta/paperboat-cli/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat-cli/internal/tunnel"
)

// fixedUploader returns a constant VM path.
type fixedUploader struct{ vmPath string }

func (u fixedUploader) UploadBatch(_ context.Context, _, _ string, sources []transfer.Source) (transfer.Batch, error) {
	paths := make([]string, len(sources))
	for i := range paths {
		paths[i] = u.vmPath
	}
	return transfer.Batch{Paths: paths}, nil
}

// failUploader always errors, exercising fail-open.
type failUploader struct{}

func (failUploader) UploadBatch(context.Context, string, string, []transfer.Source) (transfer.Batch, error) {
	return transfer.Batch{}, errors.New("boom")
}

type batchUploader struct {
	sources []transfer.Source
	result  transfer.Batch
	err     error
}

func (u *batchUploader) UploadBatch(_ context.Context, _ string, _ string, sources []transfer.Source) (transfer.Batch, error) {
	u.sources = append([]transfer.Source(nil), sources...)
	return u.result, u.err
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

func (u *blockingUploader) UploadBatch(ctx context.Context, _, _ string, sources []transfer.Source) (transfer.Batch, error) {
	u.once.Do(func() { close(u.started) })
	select {
	case <-u.release:
		return fixedUploader{"/vm/slow.png"}.UploadBatch(ctx, "", "", sources)
	case <-ctx.Done():
		return transfer.Batch{}, ctx.Err()
	}
}

func defaultLimits() transfer.Limits {
	return transfer.Limits{MaxFileBytes: 50 << 20, MaxBatchFiles: 8, MaxBatchBytes: 500 << 20}
}

func New(dest io.Writer, uploader BatchUploader, limits transfer.Limits, opts ...Option) *Interceptor {
	return NewWithPolicy(dest, NewPolicy(uploader, "ses_test", limits), opts...)
}

func wrap(body string) string {
	return "\x1b[200~" + body + "\x1b[201~"
}

func TestDefaultUploadTimeoutSupportsMaximumSizeTransfers(t *testing.T) {
	i := New(io.Discard, fixedUploader{"/unused"}, defaultLimits())
	t.Cleanup(func() { _ = i.Close() })
	if i.timeout != 10*time.Minute {
		t.Fatalf("default upload timeout = %s, want 10m", i.timeout)
	}
}

func BenchmarkDirectInput4KiB(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 4<<10)
	interceptor := New(io.Discard, fixedUploader{"/unused"}, defaultLimits(),
		WithDirectInput(), WithPartialFlushDelay(time.Hour))
	b.Cleanup(func() { _ = interceptor.Close() })
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := interceptor.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBracketedTextPaste4KiB(b *testing.B) {
	payload := []byte(wrap(string(bytes.Repeat([]byte("x"), 4<<10))))
	b.ReportAllocs()
	b.SetBytes(4 << 10)
	for range b.N {
		interceptor := New(io.Discard, fixedUploader{"/unused"}, defaultLimits(),
			WithDirectInput(), WithPartialFlushDelay(time.Hour))
		if _, err := interceptor.Write(payload); err != nil {
			b.Fatal(err)
		}
		if err := interceptor.Close(); err != nil {
			b.Fatal(err)
		}
	}
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
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	in := "hello world\nno paste here"
	writeInChunks(t, i, in, 3)
	if dest.String() != in {
		t.Fatalf("got %q want %q", dest.String(), in)
	}
}

func TestNonImagePasteUntouched(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
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
	i := New(&dest, fixedUploader{"/vm/attach/shot.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(img), 5)
	want := wrap("/vm/attach/shot.png")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestNonImageFilePasteRewritten(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/attach/notes.txt"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(file), 3)
	if got, want := dest.String(), wrap("/vm/attach/notes.txt"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestImagePastePreservesWhitespaceAndQuotes(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "quoted image.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/quoted.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap("  \""+img+"\"\t"), 4)
	if got, want := dest.String(), wrap("  /vm/quoted.png\t"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFileURLImagePaste(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "url image.png")
	fileURL := "file://" + strings.ReplaceAll(img, " ", "%20")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/url.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(fileURL), 3)
	if got, want := dest.String(), wrap("/vm/url.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFileLocalhostURLImagePaste(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "url special #.png")
	fileURL := "file://localhost" + strings.ReplaceAll(strings.ReplaceAll(img, " ", "%20"), "#", "%23")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/localhost.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(fileURL), 2)
	if got, want := dest.String(), wrap("/vm/localhost.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestShellEscapedAndPOSIXQuotedImagePastes(t *testing.T) {
	dir := t.TempDir()
	escaped := makeImage(t, dir, "wezterm image.png")
	quoted := makeImage(t, dir, "quoted $& image.png")
	for name, body := range map[string]string{
		"escaped spaces": strings.ReplaceAll(escaped, " ", "\\ "),
		"single quoted":  "'" + quoted + "'",
	} {
		t.Run(name, func(t *testing.T) {
			var dest bytes.Buffer
			i := New(&dest, fixedUploader{"/vm/staged.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
			writeInChunks(t, i, wrap(body), 3)
			if got, want := dest.String(), wrap("/vm/staged.png"); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

func TestUnsupportedPathSyntaxPassesThroughExactly(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "ordinary.png")
	for name, body := range map[string]string{
		"relative path":       "ordinary.png",
		"shell operator":      img + "; echo no",
		"expansion":           "$HOME/ordinary.png",
		"malformed quote":     "'" + img,
		"malformed escape":    img + "\\\\",
		"file query":          "file://" + img + "?x=1",
		"windows quoted path": `"C:\Users\Jane Doe\image.png"`,
	} {
		t.Run(name, func(t *testing.T) {
			var dest bytes.Buffer
			i := New(&dest, fixedUploader{"/vm/unexpected.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
			writeInChunks(t, i, wrap(body), 2)
			if got, want := dest.String(), wrap(body); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

func TestDecodePOSIXWordPreservesWindowsBackslashesInDoubleQuotes(t *testing.T) {
	got, _, ok := decodePOSIXWord(`"C:\Users\Jane Doe\image.png"`)
	if !ok || got != `C:\Users\Jane Doe\image.png` {
		t.Fatalf("decodePOSIXWord = %q, %v", got, ok)
	}
}

func TestUnframedImagePathPassesThroughExactly(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "ordinary.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/unexpected.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, img, 2)
	if got := dest.String(); got != img {
		t.Fatalf("got %q want %q", got, img)
	}
}

func TestFragmentedMultiLineEscapedImagePastes(t *testing.T) {
	dir := t.TempDir()
	a := makeImage(t, dir, "one image.png")
	b := makeImage(t, dir, "two image.png")
	body := strings.ReplaceAll(a, " ", "\\ ") + "\n'" + b + "'"
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/staged.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(body), 1)
	if got, want := dest.String(), wrap("/vm/staged.png\n/vm/staged.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestTempFilePatterns(t *testing.T) {
	dir := t.TempDir()
	allowed := makeImage(t, dir, "terminal-paste-123.png")
	rejected := makeImage(t, dir, "manual.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/allowed.png"}, defaultLimits(),
		WithWatchDirs([]string{dir}), WithTempFilePatterns([]string{"terminal-paste-*.png"}),
		WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(allowed)+wrap(rejected), 5)
	if got, want := dest.String(), wrap(rejected)+wrap("/vm/allowed.png"); got != want {
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
	policy := NewPolicy(fixedUploader{"/vm/old.png"}, "ses_1", defaultLimits())
	i := NewWithPolicy(&dest, policy, WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(img), 8)
	policy.Update(fixedUploader{"/vm/new.png"}, "ses_1", defaultLimits())
	dest.Reset()
	i = NewWithPolicy(&dest, policy, WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(img), 8)
	if got := dest.String(); got != wrap("/vm/new.png") {
		t.Fatalf("got %q", got)
	}
}

func TestFileTransferPolicyUploadsMixedBatchBeforeRewriting(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	binary := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	uploader := &batchUploader{result: transfer.Batch{Paths: []string{"/remote/empty", "/remote/archive.bin"}}}
	policy := NewPolicy(uploader, "ses_1", transfer.Limits{MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20})
	var dest bytes.Buffer
	i := NewWithPolicy(&dest, policy, WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(empty+"\n"+binary), 5)
	if got := dest.String(); got != wrap("/remote/empty\n/remote/archive.bin") {
		t.Fatalf("got=%q", got)
	}
	if len(uploader.sources) != 2 || uploader.sources[0].Size != 0 || uploader.sources[1].Size != 3 {
		t.Fatalf("sources=%#v", uploader.sources)
	}
}

func TestFileTransferBatchFailurePreservesEveryOriginalPath(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.txt")
	second := filepath.Join(dir, "b.bin")
	_ = os.WriteFile(first, []byte("a"), 0o600)
	_ = os.WriteFile(second, []byte("b"), 0o600)
	uploader := &batchUploader{err: errors.New("failed")}
	policy := NewPolicy(uploader, "ses_1", transfer.Limits{MaxBatchFiles: 10})
	var dest bytes.Buffer
	i := NewWithPolicy(&dest, policy, WithPartialFlushDelay(time.Hour))
	original := first + "\n" + second
	writeInChunks(t, i, wrap(original), 7)
	if got := dest.String(); got != wrap(original) {
		t.Fatalf("got=%q", got)
	}
}

func TestImagePasteSplitAcrossWrites(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "a.png")
	for _, chunk := range []int{1, 2, 7} {
		var dest bytes.Buffer
		i := New(&dest, fixedUploader{"/vm/a.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
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
	i := New(&dest, failUploader{}, defaultLimits(), WithNotifier(&notice), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(img), 6)
	if got := dest.String(); got != wrap(img) {
		t.Fatalf("fail-open: got %q want original %q", got, wrap(img))
	}
	if !strings.Contains(notice.String(), "file upload failed: boom; pasting original path") {
		t.Fatalf("expected the upload error in the visible notice, got %q", notice.String())
	}
}

func TestAdjacentPastes(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "c.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/c.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	in := "x" + wrap(img) + "y" + wrap("plain") + "z"
	writeInChunks(t, i, in, 3)
	want := "xy" + wrap("plain") + "z" + wrap("/vm/c.png")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestSlowUploadDoesNotBlockTerminalInput(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "slow.png")
	var dest bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits(), WithDirectInput(), WithPartialFlushDelay(time.Hour))

	writeDone := make(chan error, 1)
	go func() {
		_, err := i.Write([]byte(wrap(img)))
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
	if _, err := i.Write([]byte("typed-during-upload")); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "typed-during-upload" {
		t.Fatalf("terminal input was blocked during upload: %q", got)
	}
	close(uploader.release)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := dest.String(), "typed-during-upload"+wrap("/vm/slow.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDirectInputWritesOrdinaryBytesInline(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithDirectInput(), WithPartialFlushDelay(time.Hour))
	if _, err := i.Write([]byte("ordinary input")); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "ordinary input" {
		t.Fatalf("destination before Write returned = %q", got)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectInputRetainsOnlyPossiblePastePrefix(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithDirectInput(), WithPartialFlushDelay(time.Hour))
	if _, err := i.Write([]byte("a\x1b[2J")); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "a\x1b[2J" {
		t.Fatalf("ordinary ANSI sequence was buffered: %q", got)
	}
	if _, err := i.Write([]byte("\x1b[20")); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "a\x1b[2J" {
		t.Fatalf("possible marker prefix was emitted: %q", got)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got := dest.String(); got != "a\x1b[2J\x1b[20" {
		t.Fatalf("close did not flush retained prefix: %q", got)
	}
}

func TestDirectInputOrdinaryWriteAllocations(t *testing.T) {
	i := New(io.Discard, fixedUploader{"/vm/x.png"}, defaultLimits(), WithDirectInput(), WithPartialFlushDelay(time.Hour))
	p := []byte("x")
	allocations := testing.AllocsPerRun(1000, func() {
		if _, err := i.Write(p); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("ordinary input allocations = %v, want 0", allocations)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAbortCancelsUpload(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "cancel.png")
	var dest bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits(), WithPartialFlushDelay(time.Hour))
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
	i := New(dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	if _, err := i.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	// Wait for the uncertain write to be discarded before sending more, so
	// "second" cannot coalesce into the discarded batch.
	deadline := time.Now().Add(2 * time.Second)
	for {
		dest.mu.Lock()
		discarded := dest.discarded
		dest.mu.Unlock()
		if discarded > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("destination discard hook was not called")
		}
		time.Sleep(time.Millisecond)
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
	i := New(fatalWriter{err: want}, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
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

func TestSlowUploadDoesNotApplyInputBackpressure(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "bounded.png")
	var dest bytes.Buffer
	uploader := &blockingUploader{started: make(chan struct{}), release: make(chan struct{})}
	i := New(&dest, uploader, defaultLimits(), WithMaxQueuedBytes(8))
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
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal input blocked behind upload")
	}
	close(uploader.release)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := dest.String(), "sixteen-bytes!!!"+wrap("/vm/slow.png"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMultipleImageLines(t *testing.T) {
	dir := t.TempDir()
	a := makeImage(t, dir, "one.png")
	b := makeImage(t, dir, "two.png")
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
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
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	writeInChunks(t, i, wrap(a+"\n\n"+b+"\n"), 5)
	want := wrap("/vm/x.png\n\n/vm/x.png\n")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

func TestPartialStartMarkerHeldThenFlushed(t *testing.T) {
	var dest bytes.Buffer
	i := New(&dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
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

type syncedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestBareEscapeFlushedWithoutFurtherInput(t *testing.T) {
	dest := &syncedBuffer{}
	i := New(dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(5*time.Millisecond))
	defer i.Close()
	// A lone ESC (prefix of the paste start marker) must reach the remote on
	// its own — waiting for the next keypress makes the ESC key feel dead.
	if _, err := i.Write([]byte("\x1b")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for dest.String() != "\x1b" {
		if time.Now().After(deadline) {
			t.Fatalf("ESC not flushed; dest=%q", dest.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSplitStartMarkerWithinDelayStillIntercepted(t *testing.T) {
	dir := t.TempDir()
	img := makeImage(t, dir, "a.png")
	dest := &syncedBuffer{}
	i := New(dest, fixedUploader{"/vm/a.png"}, defaultLimits(), WithPartialFlushDelay(5*time.Second))
	if _, err := i.Write([]byte("\x1b[2")); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Write([]byte("00~" + img + "\x1b[201~")); err != nil {
		t.Fatal(err)
	}
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	want := wrap("/vm/a.png")
	if dest.String() != want {
		t.Fatalf("got %q want %q", dest.String(), want)
	}
}

// gatedWriter blocks its first Write until released, recording each Write it
// receives afterwards.
type gatedWriter struct {
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	writes  []string
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	w.mu.Lock()
	w.writes = append(w.writes, string(p))
	w.mu.Unlock()
	return len(p), nil
}

func (w *gatedWriter) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.writes...)
}

func TestQueuedInputChunksAreCoalescedIntoOneWrite(t *testing.T) {
	dest := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	i := New(dest, fixedUploader{"/vm/x.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
	if _, err := i.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	<-dest.entered // worker is stalled inside dest.Write("a")
	for _, s := range []string{"b", "c", "d"} {
		if _, err := i.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	close(dest.release)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	got := dest.snapshot()
	if len(got) != 2 || got[0] != "a" || got[1] != "bcd" {
		t.Fatalf("expected backlog coalesced into one write [a bcd], got %q", got)
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
		i := New(&dest, fixedUploader{"/vm/fuzz.png"}, defaultLimits(), WithPartialFlushDelay(time.Hour))
		writeInChunks(t, i, string(input), chunk)
		if !bytes.Equal(dest.Bytes(), input) {
			t.Fatalf("stream changed: got %q want %q", dest.Bytes(), input)
		}
	})
}

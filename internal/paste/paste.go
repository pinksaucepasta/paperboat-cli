// Package paste implements the bracketed-paste interceptor: the client-side
// stream logic that detects a pasted local image, uploads it, and rewrites the
// paste to a VM-side path before the remote agent sees it. It is the risk
// center of the CLI and is covered by unit tests.
//
// Guarantees (see AGENTS.md):
//   - Non-image pastes pass through byte-for-byte untouched.
//   - Paste framing (ESC[200~ … ESC[201~) and ordering are preserved.
//   - Upload holds only the affected paste; the rest of the stream keeps
//     flowing, and remote output runs on a separate goroutine so the PTY never
//     deadlocks.
//   - Fail open, visibly: on any detection/upload failure the original paste is
//     emitted unchanged and a notice is written to the local terminal.
package paste

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/upload"
)

var (
	startMarker = []byte("\x1b[200~")
	endMarker   = []byte("\x1b[201~")
)

// DefaultUploadTimeout bounds how long a single paste is held for upload.
const DefaultUploadTimeout = 30 * time.Second

// Interceptor wraps the writer feeding the remote PTY. Feed stdin bytes to it
// via Write; it forwards them to dest, rewriting image pastes along the way.
type Interceptor struct {
	dest      io.Writer
	up        upload.Uploader
	limits    upload.Limits
	notify    io.Writer
	timeout   time.Duration
	watchDirs []string

	buf     []byte
	inPaste bool
}

// Option configures an Interceptor.
type Option func(*Interceptor)

// WithNotifier sets where user-facing (fail-open) messages are written.
func WithNotifier(w io.Writer) Option { return func(i *Interceptor) { i.notify = w } }

// WithTimeout sets the per-paste upload timeout.
func WithTimeout(d time.Duration) Option { return func(i *Interceptor) { i.timeout = d } }

// WithWatchDirs restricts temp-image detection to these directories (in
// addition to absolute paths that exist). Empty means "any existing path".
func WithWatchDirs(dirs []string) Option { return func(i *Interceptor) { i.watchDirs = dirs } }

// New builds an Interceptor writing rewritten output to dest.
func New(dest io.Writer, up upload.Uploader, limits upload.Limits, opts ...Option) *Interceptor {
	i := &Interceptor{
		dest:    dest,
		up:      up,
		limits:  limits,
		notify:  io.Discard,
		timeout: DefaultUploadTimeout,
	}
	for _, o := range opts {
		o(i)
	}
	return i
}

// Write consumes p, forwarding processed bytes to dest. It always reports the
// full input as written (the interceptor owns buffering) unless dest errors.
func (i *Interceptor) Write(p []byte) (int, error) {
	i.buf = append(i.buf, p...)
	if err := i.drain(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes any buffered normal bytes. A partial (unterminated) paste is
// flushed verbatim so nothing is lost on disconnect.
func (i *Interceptor) Close() error {
	if len(i.buf) == 0 {
		return nil
	}
	// Emit whatever remains: if mid-paste, re-add the start marker so framing
	// stays well-formed for the remote.
	var out []byte
	if i.inPaste {
		out = append(out, startMarker...)
	}
	out = append(out, i.buf...)
	i.buf = nil
	i.inPaste = false
	_, err := i.dest.Write(out)
	return err
}

// drain processes as much of buf as possible without blocking on partial
// markers that may complete in a later Write.
func (i *Interceptor) drain() error {
	for {
		if !i.inPaste {
			done, err := i.drainNormal()
			if err != nil || !done {
				return err
			}
			continue
		}
		done, err := i.drainPaste()
		if err != nil || !done {
			return err
		}
	}
}

// drainNormal emits non-paste bytes up to the next start marker. It returns
// done=true when it consumed a full start marker (more work may remain).
func (i *Interceptor) drainNormal() (done bool, err error) {
	idx := bytes.Index(i.buf, startMarker)
	if idx < 0 {
		// No complete start marker. Flush everything except a suffix that could
		// be the beginning of a start marker split across Writes.
		keep := partialSuffix(i.buf, startMarker)
		flush := i.buf[:len(i.buf)-keep]
		if len(flush) > 0 {
			if _, err := i.dest.Write(flush); err != nil {
				return false, err
			}
		}
		i.buf = append(i.buf[:0], i.buf[len(i.buf)-keep:]...)
		return false, nil
	}
	// Emit the normal bytes before the marker, then enter paste mode. The start
	// marker itself is consumed here and re-emitted when the paste is flushed.
	if idx > 0 {
		if _, err := i.dest.Write(i.buf[:idx]); err != nil {
			return false, err
		}
	}
	i.buf = append(i.buf[:0], i.buf[idx+len(startMarker):]...)
	i.inPaste = true
	return true, nil
}

// drainPaste waits for a complete paste, then processes and emits it. It
// returns done=true when a full paste was handled.
func (i *Interceptor) drainPaste() (done bool, err error) {
	idx := bytes.Index(i.buf, endMarker)
	if idx < 0 {
		// Whole (possibly large) paste body not yet complete; wait for more.
		return false, nil
	}
	body := append([]byte(nil), i.buf[:idx]...)
	i.buf = append(i.buf[:0], i.buf[idx+len(endMarker):]...)
	i.inPaste = false

	out := i.rewrite(body)
	framed := make([]byte, 0, len(startMarker)+len(out)+len(endMarker))
	framed = append(framed, startMarker...)
	framed = append(framed, out...)
	framed = append(framed, endMarker...)
	if _, err := i.dest.Write(framed); err != nil {
		return false, err
	}
	return true, nil
}

// rewrite returns the paste body to emit. If the body is one-or-more local
// image paths, each is uploaded and replaced by its VM path. Any failure falls
// back to the original body (fail open) with a local notice.
func (i *Interceptor) rewrite(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	candidates := make([]string, 0, len(lines))
	nonEmpty := 0
	for _, ln := range lines {
		p, ok := candidatePath(ln)
		if strings.TrimSpace(ln) != "" {
			nonEmpty++
		}
		if !ok || !i.isLocalImage(p) {
			return body // not a pure image paste — leave untouched
		}
		candidates = append(candidates, p)
	}
	if nonEmpty == 0 {
		return body
	}
	if i.limits.MaxAttachments > 0 && nonEmpty > i.limits.MaxAttachments {
		i.warn("paste has %d images, over the limit of %d; sending as-is", nonEmpty, i.limits.MaxAttachments)
		return body
	}

	ctx := context.Background()
	if i.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, i.timeout)
		defer cancel()
	}

	out := make([]string, len(lines))
	for idx, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			out[idx] = ln
			continue
		}
		local, _ := candidatePath(ln)
		vmPath, err := i.uploadOne(ctx, local)
		if err != nil {
			i.warn("image upload failed (%v); pasting original path", err)
			return body // fail open for the whole paste
		}
		out[idx] = vmPath
	}
	return []byte(strings.Join(out, "\n"))
}

func (i *Interceptor) uploadOne(ctx context.Context, path string) (string, error) {
	img, err := upload.PrepareImage(path, i.limits)
	if err != nil {
		return "", err
	}
	return i.up.Upload(ctx, img)
}

// isLocalImage reports whether p points at an existing local image file,
// honoring configured watch dirs when set.
func (i *Interceptor) isLocalImage(p string) bool {
	if !upload.IsImagePath(p) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return false
	}
	if len(i.watchDirs) == 0 {
		return true
	}
	for _, d := range i.watchDirs {
		if within(d, p) {
			return true
		}
	}
	return false
}

func (i *Interceptor) warn(format string, args ...any) {
	fmt.Fprintf(i.notify, "\r\n[paperboat] "+format+"\r\n", args...)
}

// candidatePath extracts a filesystem path from a pasted line, stripping quotes
// and a file:// scheme. ok is false for blank lines.
func candidatePath(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", false
	}
	s = strings.Trim(s, "\"'")
	s = strings.TrimPrefix(s, "file://")
	if s == "" {
		return "", false
	}
	return s, true
}

// partialSuffix returns the length of the longest suffix of buf that is a
// proper prefix of marker (so those bytes are withheld until the next Write).
func partialSuffix(buf, marker []byte) int {
	max := len(marker) - 1
	if len(buf) < max {
		max = len(buf)
	}
	for n := max; n > 0; n-- {
		if bytes.Equal(buf[len(buf)-n:], marker[:n]) {
			return n
		}
	}
	return 0
}

func within(dir, path string) bool {
	dir = strings.TrimRight(dir, string(os.PathSeparator))
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}

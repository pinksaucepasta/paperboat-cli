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
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
	"github.com/pujan-modha/paperboat-cli/internal/upload"
)

var (
	startMarker = []byte("\x1b[200~")
	endMarker   = []byte("\x1b[201~")
)

// DefaultUploadTimeout bounds how long a single paste is held for upload.
const DefaultUploadTimeout = 30 * time.Second

const (
	defaultQueueChunkSize = 32 * 1024
	defaultQueueChunks    = 32
)

// Interceptor wraps the writer feeding the remote PTY. Feed stdin bytes to it
// via Write; it forwards them to dest, rewriting image pastes along the way.
type Interceptor struct {
	ctx            context.Context
	cancel         context.CancelFunc
	policy         *Policy
	dest           io.Writer
	notify         io.Writer
	timeout        time.Duration
	watchDirs      []string
	tempPatterns   []string
	queueChunkSize int
	queueChunks    int
	input          chan []byte
	done           chan struct{}
	closeOnce      sync.Once
	lifecycleMu    sync.RWMutex
	closed         bool
	pressureOnce   sync.Once
	stateMu        sync.Mutex
	errMu          sync.Mutex
	err            error
	errCh          chan error

	buf     []byte
	inPaste bool
}

type Policy struct {
	mu       sync.RWMutex
	uploader upload.Uploader
	limits   upload.Limits
}

func NewPolicy(uploader upload.Uploader, limits upload.Limits) *Policy {
	return &Policy{uploader: uploader, limits: limits}
}
func (p *Policy) Update(uploader upload.Uploader, limits upload.Limits) {
	p.mu.Lock()
	p.uploader = uploader
	p.limits = limits
	p.mu.Unlock()
}
func (p *Policy) snapshot() (upload.Uploader, upload.Limits) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.uploader, p.limits
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

// WithTempFilePatterns restricts recognized terminal temp files by glob.
func WithTempFilePatterns(patterns []string) Option {
	return func(i *Interceptor) { i.tempPatterns = append([]string(nil), patterns...) }
}

// WithMaxQueuedBytes bounds input held behind an in-flight image upload.
func WithMaxQueuedBytes(n int) Option {
	return func(i *Interceptor) {
		if n <= 0 {
			return
		}
		i.queueChunkSize = defaultQueueChunkSize
		if n < i.queueChunkSize {
			i.queueChunkSize = n
		}
		i.queueChunks = (n + i.queueChunkSize - 1) / i.queueChunkSize
	}
}

// New builds an Interceptor writing rewritten output to dest.
func New(dest io.Writer, up upload.Uploader, limits upload.Limits, opts ...Option) *Interceptor {
	return NewWithPolicy(dest, NewPolicy(up, limits), opts...)
}

func NewWithPolicy(dest io.Writer, policy *Policy, opts ...Option) *Interceptor {
	ctx, cancel := context.WithCancel(context.Background())
	i := &Interceptor{
		ctx:            ctx,
		cancel:         cancel,
		policy:         policy,
		dest:           dest,
		notify:         io.Discard,
		timeout:        DefaultUploadTimeout,
		queueChunkSize: defaultQueueChunkSize,
		queueChunks:    defaultQueueChunks,
	}
	for _, o := range opts {
		o(i)
	}
	i.input = make(chan []byte, i.queueChunks)
	i.done = make(chan struct{})
	i.errCh = make(chan error, 1)
	go i.run()
	return i
}

// Abort cancels any in-flight upload during terminal teardown.
func (i *Interceptor) Abort() {
	i.setError(context.Canceled)
	i.cancel()
}
func (i *Interceptor) Discard() {
	i.stateMu.Lock()
	i.buf = nil
	i.inPaste = false
	i.stateMu.Unlock()
}

// Write consumes p, forwarding processed bytes to dest. It always reports the
// full input as written (the interceptor owns buffering) unless dest errors.
func (i *Interceptor) Write(p []byte) (int, error) {
	i.lifecycleMu.RLock()
	defer i.lifecycleMu.RUnlock()
	if i.closed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		select {
		case <-i.done:
			return written, i.result()
		default:
		}
		n := len(p)
		if n > i.queueChunkSize {
			n = i.queueChunkSize
		}
		chunk := append([]byte(nil), p[:n]...)
		select {
		case i.input <- chunk:
			written += n
			p = p[n:]
			select {
			case <-i.done:
				return written, i.result()
			default:
			}
			continue
		default:
			i.pressureOnce.Do(func() {
				i.warn("local input queue is full; waiting for image upload")
			})
		}
		select {
		case i.input <- chunk:
			written += n
			p = p[n:]
			select {
			case <-i.done:
				return written, i.result()
			default:
			}
		case <-i.done:
			return written, i.result()
		case <-i.ctx.Done():
			return written, i.ctx.Err()
		}
	}
	return written, nil
}

// Close flushes any buffered normal bytes. A partial (unterminated) paste is
// flushed verbatim so nothing is lost on disconnect.
func (i *Interceptor) Close() error {
	i.closeOnce.Do(func() {
		i.lifecycleMu.Lock()
		i.closed = true
		close(i.input)
		i.lifecycleMu.Unlock()
	})
	<-i.done
	return i.result()
}

// Errors reports fatal asynchronous destination failures to the session loop.
func (i *Interceptor) Errors() <-chan error { return i.errCh }

func (i *Interceptor) run() {
	defer close(i.done)
	for {
		select {
		case <-i.ctx.Done():
			i.setError(i.ctx.Err())
			return
		case p, ok := <-i.input:
			if !ok {
				i.stateMu.Lock()
				err := i.flush()
				i.stateMu.Unlock()
				i.setError(err)
				return
			}
			i.stateMu.Lock()
			i.buf = append(i.buf, p...)
			err := i.drain()
			i.stateMu.Unlock()
			if err != nil {
				if errors.Is(err, tunnel.ErrWriteUncertain) {
					i.Discard()
					if discarder, ok := i.dest.(interface{ Discard() }); ok {
						discarder.Discard()
					}
					continue
				}
				i.setError(err)
				return
			}
		}
	}
}

func (i *Interceptor) flush() error {
	if len(i.buf) == 0 && !i.inPaste {
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

func (i *Interceptor) setError(err error) {
	if err == nil {
		return
	}
	i.errMu.Lock()
	if i.err == nil {
		i.err = err
		select {
		case i.errCh <- err:
		default:
		}
	}
	i.errMu.Unlock()
}

func (i *Interceptor) result() error {
	i.errMu.Lock()
	defer i.errMu.Unlock()
	return i.err
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
	candidates := make([]pathCandidate, len(lines))
	defer func() {
		for _, candidate := range candidates {
			if candidate.file != nil {
				_ = candidate.file.Close()
			}
		}
	}()
	nonEmpty := 0
	for idx, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		nonEmpty++
		candidate, ok := parseCandidate(ln)
		if !ok {
			return body // not a pure image paste — leave untouched
		}
		resolved, file, ok := i.openLocalImage(candidate.path)
		if !ok {
			return body
		}
		candidate.path = resolved
		candidate.file = file
		candidates[idx] = candidate
	}
	if nonEmpty == 0 {
		return body
	}
	uploader, limits := i.policy.snapshot()
	if limits.MaxAttachments > 0 && nonEmpty > limits.MaxAttachments {
		i.warn("paste has %d images, over the limit of %d; sending as-is", nonEmpty, limits.MaxAttachments)
		return body
	}

	ctx := i.ctx
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
		candidate := candidates[idx]
		vmPath, err := uploadOne(ctx, uploader, limits, candidate)
		if err != nil {
			i.warn("image upload failed; pasting original path")
			return body // fail open for the whole paste
		}
		out[idx] = ln[:candidate.start] + vmPath + ln[candidate.end:]
	}
	return []byte(strings.Join(out, "\n"))
}

func uploadOne(ctx context.Context, uploader upload.Uploader, limits upload.Limits, candidate pathCandidate) (string, error) {
	img, err := upload.PrepareImageFile(candidate.file, candidate.path, limits)
	if err != nil {
		return "", err
	}
	return uploader.Upload(ctx, img)
}

// isLocalImage reports whether p points at an existing local image file,
// honoring configured watch dirs when set.
func (i *Interceptor) openLocalImage(p string) (string, *os.File, bool) {
	if !upload.IsImagePath(p) {
		return "", nil, false
	}
	file, err := os.Open(p)
	if err != nil {
		return "", nil, false
	}
	fail := func() (string, *os.File, bool) {
		_ = file.Close()
		return "", nil, false
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() {
		return fail()
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return fail()
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return fail()
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil || !resolvedInfo.Mode().IsRegular() || !os.SameFile(openedInfo, resolvedInfo) {
		return fail()
	}
	if len(i.watchDirs) == 0 {
		if i.matchesTempPattern(resolved) {
			return resolved, file, true
		}
		return fail()
	}
	for _, d := range i.watchDirs {
		resolvedDir, dirErr := filepath.EvalSymlinks(d)
		if dirErr != nil {
			continue
		}
		resolvedDir, dirErr = filepath.Abs(resolvedDir)
		if dirErr == nil && within(resolvedDir, resolved) {
			if i.matchesTempPattern(resolved) {
				return resolved, file, true
			}
			return fail()
		}
	}
	return fail()
}

func (i *Interceptor) matchesTempPattern(p string) bool {
	if len(i.tempPatterns) == 0 {
		return true
	}
	base := filepath.Base(p)
	normalized := filepath.ToSlash(p)
	for _, pattern := range i.tempPatterns {
		baseMatch, baseErr := filepath.Match(pattern, base)
		pathMatch, pathErr := path.Match(filepath.ToSlash(pattern), normalized)
		if (baseErr == nil && baseMatch) || (pathErr == nil && pathMatch) {
			return true
		}
	}
	return false
}

func (i *Interceptor) warn(format string, args ...any) {
	fmt.Fprintf(i.notify, "\r\n[paperboat] "+format+"\r\n", args...)
}

type pathCandidate struct {
	path       string
	file       *os.File
	start, end int
}

// parseCandidate accepts exactly one path token with optional surrounding
// whitespace and one matching quote pair. start/end identify only that token
// so rewriting preserves the rest of the original paste line byte-for-byte.
func parseCandidate(line string) (pathCandidate, bool) {
	trimmedLeft := strings.TrimLeft(line, " \t\r")
	start := len(line) - len(trimmedLeft)
	trimmed := strings.TrimRight(trimmedLeft, " \t\r")
	end := start + len(trimmed)
	if start == end {
		return pathCandidate{}, false
	}
	if trimmed[0] == '\'' || trimmed[0] == '"' {
		if len(trimmed) < 2 || trimmed[len(trimmed)-1] != trimmed[0] {
			return pathCandidate{}, false
		}
		start++
		end--
		trimmed = trimmed[1 : len(trimmed)-1]
	} else if trimmed[len(trimmed)-1] == '\'' || trimmed[len(trimmed)-1] == '"' {
		return pathCandidate{}, false
	}
	if trimmed == "" {
		return pathCandidate{}, false
	}
	localPath := trimmed
	if strings.HasPrefix(strings.ToLower(trimmed), "file:") {
		u, err := url.Parse(trimmed)
		if err != nil || !strings.EqualFold(u.Scheme, "file") ||
			(u.Host != "" && !strings.EqualFold(u.Host, "localhost")) ||
			u.RawQuery != "" || u.Fragment != "" || u.Path == "" {
			return pathCandidate{}, false
		}
		localPath = u.Path
		if runtime.GOOS == "windows" && len(localPath) >= 3 && localPath[0] == '/' && localPath[2] == ':' {
			localPath = localPath[1:]
		}
	}
	return pathCandidate{path: filepath.FromSlash(localPath), start: start, end: end}, true
}

func candidatePath(line string) (string, bool) {
	candidate, ok := parseCandidate(line)
	return candidate.path, ok
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
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

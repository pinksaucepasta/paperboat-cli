// Package paste implements the bracketed-paste interceptor: the client-side
// stream logic that detects a pasted local image, uploads it, and rewrites the
// paste to a VM-side path before the remote agent sees it. It is the risk
// center of the CLI and is covered by unit tests.
//
// Guarantees (see AGENTS.md):
//   - Pasted text that is not a validated absolute file path passes through untouched.
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
	"sync/atomic"
	"time"

	transfer "github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

var (
	startMarker = []byte("\x1b[200~")
	endMarker   = []byte("\x1b[201~")
)

// DefaultUploadTimeout bounds how long a single paste is held for upload.
const DefaultUploadTimeout = 10 * time.Minute

// DefaultPartialFlushDelay bounds how long bytes that could begin a paste
// start marker (e.g. a bare ESC keypress) are withheld while waiting for the
// rest of the marker. Without this flush, a lone ESC would not reach the
// remote TUI until the next keypress.
const DefaultPartialFlushDelay = time.Millisecond

const (
	defaultQueueChunkSize = 32 * 1024
	defaultQueueChunks    = 32
)

// Interceptor wraps the writer feeding the remote PTY. Feed stdin bytes to it
// via Write; it forwards them to dest, rewriting local file-path pastes along the way.
type Interceptor struct {
	ctx            context.Context
	cancel         context.CancelFunc
	policy         *Policy
	dest           io.Writer
	notify         io.Writer
	timeout        time.Duration
	flushDelay     time.Duration
	watchDirs      []string
	tempPatterns   []string
	queueChunkSize int
	queueChunks    int
	input          chan []byte
	completed      chan uploadCompletion
	done           chan struct{}
	closeOnce      sync.Once
	lifecycleMu    sync.RWMutex
	closed         bool
	pressureOnce   sync.Once
	queued         atomic.Int64
	pendingUploads atomic.Int64
	uploadSeq      atomic.Uint64
	destMu         sync.Mutex
	directInput    bool
	lifecycle      func(LifecycleEvent)
	stateMu        sync.Mutex
	errMu          sync.Mutex
	err            error
	errCh          chan error

	buf     []byte
	inPaste bool
}

type Policy struct {
	mu             sync.RWMutex
	transfer       BatchUploader
	transferLimits transfer.Limits
	sessionID      string
}

type BatchUploader interface {
	SendBatch(context.Context, string, string, []transfer.Source) (transfer.Batch, error)
}
type uploadCompletion struct {
	seq    uint64
	framed []byte
	err    error
}
type policySnapshot struct {
	transfer       BatchUploader
	transferLimits transfer.Limits
	sessionID      string
}

func NewPolicy(uploader BatchUploader, sessionID string, limits transfer.Limits) *Policy {
	return &Policy{transfer: uploader, sessionID: sessionID, transferLimits: limits}
}
func (p *Policy) Update(uploader BatchUploader, sessionID string, limits transfer.Limits) {
	p.mu.Lock()
	p.transfer, p.sessionID, p.transferLimits = uploader, sessionID, limits
	p.mu.Unlock()
}
func (p *Policy) snapshot() policySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return policySnapshot{p.transfer, p.transferLimits, p.sessionID}
}

// Option configures an Interceptor.
type Option func(*Interceptor)

// LifecycleEvent is metadata-only so status renderers never receive local
// paths, remote paths, or raw server errors.
type LifecycleEvent string

const (
	FileDetected  LifecycleEvent = "detected"
	FileUploading LifecycleEvent = "uploading"
	FileComplete  LifecycleEvent = "complete"
	FileFailed    LifecycleEvent = "failed"
)

// WithNotifier sets where user-facing (fail-open) messages are written.
func WithNotifier(w io.Writer) Option { return func(i *Interceptor) { i.notify = w } }

// WithLifecycle reports image-paste lifecycle transitions.
func WithLifecycle(callback func(LifecycleEvent)) Option {
	return func(i *Interceptor) { i.lifecycle = callback }
}

// WithTimeout sets the per-paste upload timeout.

// WithPartialFlushDelay sets how long a partial paste start marker is withheld
// before being forwarded as ordinary input. Zero or negative disables the
// flush (partial prefixes wait for the next write indefinitely).
func WithPartialFlushDelay(d time.Duration) Option {
	return func(i *Interceptor) { i.flushDelay = d }
}

// WithWatchDirs restricts temp-image detection to these directories (in
// addition to absolute paths that exist). Empty means "any existing path".
func WithWatchDirs(dirs []string) Option { return func(i *Interceptor) { i.watchDirs = dirs } }

// WithTempFilePatterns restricts recognized terminal temp files by glob.
func WithTempFilePatterns(patterns []string) Option {
	return func(i *Interceptor) { i.tempPatterns = append([]string(nil), patterns...) }
}

// WithMaxQueuedBytes bounds input held behind an in-flight file upload.
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

// WithDirectInput sends ordinary non-paste bytes to the destination inline.
// Only possible bracketed-paste markers enter the asynchronous upload queue.
func WithDirectInput() Option { return func(i *Interceptor) { i.directInput = true } }

func NewWithPolicy(dest io.Writer, policy *Policy, opts ...Option) *Interceptor {
	ctx, cancel := context.WithCancel(context.Background())
	i := &Interceptor{
		ctx:            ctx,
		cancel:         cancel,
		policy:         policy,
		dest:           dest,
		notify:         io.Discard,
		timeout:        DefaultUploadTimeout,
		flushDelay:     DefaultPartialFlushDelay,
		queueChunkSize: defaultQueueChunkSize,
		queueChunks:    defaultQueueChunks,
	}
	for _, o := range opts {
		o(i)
	}
	i.input = make(chan []byte, i.queueChunks)
	i.completed = make(chan uploadCompletion, 16)
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
	if i.directInput && len(p) > 0 && i.queued.Load() == 0 && i.stateMu.TryLock() {
		if !i.inPaste && len(i.buf) == 0 && !bytes.Contains(p, startMarker) && partialSuffix(p, startMarker) == 0 {
			n, err := i.writeDest(p)
			i.stateMu.Unlock()
			if errors.Is(err, tunnel.ErrWriteUncertain) {
				if discarder, ok := i.dest.(interface{ Discard() }); ok {
					discarder.Discard()
				}
				return len(p), nil
			}
			if err != nil {
				i.setError(err)
			}
			return n, err
		}
		i.stateMu.Unlock()
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
		i.queued.Add(1)
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
				i.warn("local input queue is full; waiting for file upload")
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
			i.queued.Add(-1)
			return written, i.result()
		case <-i.ctx.Done():
			i.queued.Add(-1)
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
	// flushTimer forwards a withheld partial start-marker prefix (e.g. a bare
	// ESC keypress) when the rest of the marker does not arrive in time. Real
	// paste markers arrive in a single terminal write, so the timer firing
	// means the bytes were keyboard input, not a paste.
	flushTimer := time.NewTimer(time.Hour)
	if !flushTimer.Stop() {
		<-flushTimer.C
	}
	defer flushTimer.Stop()
	timerArmed := false
	inputClosed := false
	input := i.input
	nextCompletion := uint64(0)
	completionBuffer := make(map[uint64]uploadCompletion)
	rearmFlush := func() {
		if timerArmed {
			if !flushTimer.Stop() {
				<-flushTimer.C
			}
			timerArmed = false
		}
		if i.flushDelay <= 0 {
			return
		}
		i.stateMu.Lock()
		pending := !i.inPaste && len(i.buf) > 0
		i.stateMu.Unlock()
		if pending {
			flushTimer.Reset(i.flushDelay)
			timerArmed = true
		}
	}
	// An upload completion may race with ordinary bytes that were already
	// accepted by Write. Drain that accepted input before publishing the
	// completion so a later paste cannot overtake bytes that followed it in
	// the terminal stream.
	drainAcceptedInput := func() error {
		for input != nil {
			select {
			case p, ok := <-input:
				if !ok {
					inputClosed = true
					input = nil
					return nil
				}
				i.queued.Add(-1)
				i.stateMu.Lock()
				i.buf = append(i.buf, p...)
				err := i.drain()
				i.stateMu.Unlock()
				if err != nil {
					return err
				}
			default:
				return nil
			}
		}
		return nil
	}
	handleWriteErr := func(err error) (fatal bool) {
		if errors.Is(err, tunnel.ErrWriteUncertain) {
			i.Discard()
			if discarder, ok := i.dest.(interface{ Discard() }); ok {
				discarder.Discard()
			}
			return false
		}
		i.setError(err)
		return true
	}
	for {
		select {
		case <-i.ctx.Done():
			i.setError(i.ctx.Err())
			return
		case <-flushTimer.C:
			timerArmed = false
			i.stateMu.Lock()
			var err error
			if !i.inPaste && len(i.buf) > 0 {
				out := i.buf
				i.buf = nil
				_, err = i.writeDest(out)
			}
			i.stateMu.Unlock()
			if err != nil && handleWriteErr(err) {
				return
			}
		case completion := <-i.completed:
			if err := drainAcceptedInput(); err != nil && handleWriteErr(err) {
				return
			}
			completionBuffer[completion.seq] = completion
			for {
				ready, ok := completionBuffer[nextCompletion]
				if !ok {
					break
				}
				delete(completionBuffer, nextCompletion)
				nextCompletion++
				if _, err := i.writeDest(ready.framed); err != nil && handleWriteErr(err) {
					return
				}
				if ready.err != nil {
					i.report(FileFailed)
				} else {
					i.report(FileComplete)
				}
				i.pendingUploads.Add(-1)
			}
			if inputClosed && i.pendingUploads.Load() == 0 {
				return
			}
		case p, ok := <-input:
			if !ok {
				inputClosed = true
				input = nil
				i.stateMu.Lock()
				err := i.flush()
				i.stateMu.Unlock()
				i.setError(err)
				if i.pendingUploads.Load() == 0 {
					return
				}
				continue
			}
			i.stateMu.Lock()
			i.buf = append(i.buf, p...)
			processed := int64(1)
			// Coalesce input that queued up while this worker was busy (e.g.
			// behind a slow destination write) so the backlog is forwarded in
			// one destination write instead of one write per chunk.
			batchInputClosed := false
		coalesce:
			for {
				select {
				case q, more := <-i.input:
					if !more {
						batchInputClosed = true
						break coalesce
					}
					i.buf = append(i.buf, q...)
					processed++
				default:
					break coalesce
				}
			}
			// These chunks are no longer queued once this worker owns them. In
			// particular, ordinary input must be able to take the direct path
			// while an upload started by this batch is still in flight.
			i.queued.Add(-processed)
			err := i.drain()
			if err == nil && batchInputClosed {
				err = i.flush()
			}
			i.stateMu.Unlock()
			if err != nil && handleWriteErr(err) {
				return
			}
			if batchInputClosed {
				inputClosed = true
				input = nil
			}
			if inputClosed && i.pendingUploads.Load() == 0 {
				return
			}
			rearmFlush()
		}
	}
}

func (i *Interceptor) writeDest(p []byte) (int, error) {
	i.destMu.Lock()
	defer i.destMu.Unlock()
	return i.dest.Write(p)
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
	_, err := i.writeDest(out)
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
			if _, err := i.writeDest(flush); err != nil {
				return false, err
			}
		}
		i.buf = append(i.buf[:0], i.buf[len(i.buf)-keep:]...)
		return false, nil
	}
	// Emit the normal bytes before the marker, then enter paste mode. The start
	// marker itself is consumed here and re-emitted when the paste is flushed.
	if idx > 0 {
		if _, err := i.writeDest(i.buf[:idx]); err != nil {
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

	out, pending := i.rewrite(body)
	if pending {
		return true, nil
	}
	framed := make([]byte, 0, len(startMarker)+len(out)+len(endMarker))
	framed = append(framed, startMarker...)
	framed = append(framed, out...)
	framed = append(framed, endMarker...)
	if _, err := i.writeDest(framed); err != nil {
		return false, err
	}
	return true, nil
}

// rewrite returns the paste body to emit. If the body is one-or-more local
// file paths, each is uploaded and replaced by its VM path. Any failure falls
// back to the original body (fail open) with a local notice.
func (i *Interceptor) rewrite(body []byte) ([]byte, bool) {
	lines := strings.Split(string(body), "\n")
	candidates := make([]pathCandidate, len(lines))
	owned := true
	defer func() {
		if owned {
			closeCandidates(candidates)
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
			return body, false // not a pure file-path paste; leave untouched
		}
		resolved, file, ok := i.openLocalFile(candidate.path)
		if !ok {
			return body, false
		}
		candidate.path = resolved
		candidate.file = file
		candidates[idx] = candidate
		i.report(FileDetected)
	}
	if nonEmpty == 0 {
		return body, false
	}
	policy := i.policy.snapshot()
	maxFiles := policy.transferLimits.MaxBatchFiles
	if maxFiles > 0 && nonEmpty > maxFiles {
		i.warn("paste has %d files, over the limit of %d; sending as-is", nonEmpty, maxFiles)
		return body, false
	}
	if policy.transfer != nil {
		paths := make([]string, 0, nonEmpty)
		files := make([]*os.File, 0, nonEmpty)
		for _, candidate := range candidates {
			if candidate.file != nil {
				paths = append(paths, candidate.path)
				files = append(files, candidate.file)
			}
		}
		i.report(FileUploading)
		bodyCopy := append([]byte(nil), body...)
		linesCopy := append([]string(nil), lines...)
		candidateCopy := append([]pathCandidate(nil), candidates...)
		i.pendingUploads.Add(1)
		seq := i.uploadSeq.Add(1) - 1
		owned = false
		go i.uploadAsync(seq, policy, paths, files, bodyCopy, linesCopy, candidateCopy, nonEmpty)
		return nil, true
	}

	i.warn("file transfer unavailable; pasting original path")
	return body, false
}

func closeCandidates(candidates []pathCandidate) {
	for _, candidate := range candidates {
		if candidate.file != nil {
			_ = candidate.file.Close()
		}
	}
}

func (i *Interceptor) uploadAsync(seq uint64, policy policySnapshot, paths []string, files []*os.File, body []byte, lines []string, candidates []pathCandidate, nonEmpty int) {
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	ctx := i.ctx
	if i.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, i.timeout)
		defer cancel()
	}
	sources, err := transfer.PrepareDescriptors(paths, files, policy.transferLimits)
	if err == nil {
		batchID, batchErr := transfer.NewBatchID()
		if batchErr != nil {
			err = batchErr
		} else {
			var batch transfer.Batch
			batch, err = policy.transfer.SendBatch(ctx, batchID, policy.sessionID, sources)
			if err == nil && len(batch.Paths) != nonEmpty {
				err = errors.New("helper returned incomplete file batch")
			}
			if err == nil {
				out := make([]string, len(lines))
				result := 0
				for idx, line := range lines {
					if strings.TrimSpace(line) == "" {
						out[idx] = line
						continue
					}
					candidate := candidates[idx]
					out[idx] = line[:candidate.start] + batch.Paths[result] + line[candidate.end:]
					result++
				}
				body = []byte(strings.Join(out, "\n"))
			}
		}
	}
	if err != nil {
		i.warn("file upload failed: %v; pasting original path", err)
	}
	framed := make([]byte, 0, len(startMarker)+len(body)+len(endMarker))
	framed = append(framed, startMarker...)
	framed = append(framed, body...)
	framed = append(framed, endMarker...)
	select {
	case i.completed <- uploadCompletion{seq: seq, framed: framed, err: err}:
	case <-i.ctx.Done():
	}
}

func (i *Interceptor) report(event LifecycleEvent) {
	if i.lifecycle != nil {
		i.lifecycle(event)
	}
}

// openLocalFile reports whether p points at an existing local regular file,
// honoring configured watch dirs when set.
func (i *Interceptor) openLocalFile(p string) (string, *os.File, bool) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", nil, false
	}
	pathInfo, err := os.Lstat(p)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
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
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return fail()
	}
	resolved := p
	watchPath, watchErr := filepath.EvalSymlinks(p)
	if watchErr != nil {
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
		if dirErr == nil && within(resolvedDir, watchPath) {
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

// parseCandidate accepts exactly one POSIX shell word with optional surrounding
// whitespace. It deliberately decodes only syntax that has one unambiguous
// literal value, rejecting operators, expansions, and malformed quoting.
// start/end identify the complete source word so staged paths replace any
// source quoting; staged names are safe absolute paths generated remotely.
func parseCandidate(line string) (pathCandidate, bool) {
	trimmedLeft := strings.TrimLeft(line, " \t\r")
	start := len(line) - len(trimmedLeft)
	trimmed := strings.TrimRight(trimmedLeft, " \t\r")
	end := start + len(trimmed)
	if start == end {
		return pathCandidate{}, false
	}
	var localPath string
	var hasUnquotedGlob, ok bool
	if runtime.GOOS == "windows" && strings.HasPrefix(strings.ToLower(trimmed), "file://") {
		// Keep backslashes in legacy Windows file URIs intact. POSIX shell
		// decoding would incorrectly consume them before URI handling.
		localPath, ok = trimmed, true
	} else {
		localPath, hasUnquotedGlob, ok = decodeCandidateWord(trimmed)
	}
	if !ok || localPath == "" {
		return pathCandidate{}, false
	}
	if strings.HasPrefix(strings.ToLower(localPath), "file:") {
		if runtime.GOOS == "windows" {
			// Terminal applications commonly emit the legacy Windows spelling
			// file://C:\\path or file://localhostC:\\path rather than a
			// standards-compliant file:///C:/path URI. Accept only those
			// unambiguous local-drive forms.
			raw := localPath[len("file://"):]
			if strings.HasPrefix(strings.ToLower(raw), "localhost") {
				raw = raw[len("localhost"):]
			}
			if len(raw) >= 2 && raw[1] == ':' && ((raw[0] >= 'a' && raw[0] <= 'z') || (raw[0] >= 'A' && raw[0] <= 'Z')) {
				decoded, decodeErr := url.PathUnescape(raw)
				if decodeErr != nil {
					return pathCandidate{}, false
				}
				localPath = decoded
				goto filePathDecoded
			}
		}
		u, err := url.Parse(localPath)
		if err != nil || !strings.EqualFold(u.Scheme, "file") ||
			(u.Host != "" && !strings.EqualFold(u.Host, "localhost")) ||
			u.RawQuery != "" || u.Fragment != "" || u.Path == "" {
			return pathCandidate{}, false
		}
		localPath = u.Path
		if runtime.GOOS == "windows" && len(localPath) >= 3 && localPath[0] == '/' && localPath[2] == ':' {
			localPath = localPath[1:]
		}
	} else if hasUnquotedGlob {
		return pathCandidate{}, false
	}
filePathDecoded:
	localPath = filepath.FromSlash(localPath)
	if !filepath.IsAbs(localPath) {
		return pathCandidate{}, false
	}
	return pathCandidate{path: localPath, start: start, end: end}, true
}

func decodeCandidateWord(word string) (string, bool, bool) {
	if runtime.GOOS == "windows" {
		candidate := word
		if len(candidate) >= 2 && (candidate[0] == '"' && candidate[len(candidate)-1] == '"' || candidate[0] == '\'' && candidate[len(candidate)-1] == '\'') {
			candidate = candidate[1 : len(candidate)-1]
		}
		if strings.Contains(candidate, `\ `) && filepath.IsAbs(filepath.FromSlash(candidate)) {
			return strings.ReplaceAll(candidate, `\ `, " "), false, true
		}
		if !strings.ContainsAny(candidate, "\x00\r\n") && filepath.IsAbs(filepath.FromSlash(candidate)) {
			return candidate, false, true
		}
	}
	return decodePOSIXWord(word)
}

// decodePOSIXWord decodes one shell word without invoking a shell. The return
// value records unquoted glob characters, which are only allowed for file URIs
// long enough to reject their query/fragment syntax separately.
func decodePOSIXWord(word string) (decoded string, hasUnquotedGlob bool, ok bool) {
	var out strings.Builder
	for pos := 0; pos < len(word); {
		switch word[pos] {
		case '\'', '"':
			quote := word[pos]
			pos++
			closed := false
			for pos < len(word) {
				ch := word[pos]
				if ch == quote {
					pos++
					closed = true
					break
				}
				if quote == '"' && (ch == '$' || ch == '`') {
					return "", false, false
				}
				if ch == '\\' {
					if pos+1 >= len(word) || word[pos+1] == '\n' {
						return "", false, false
					}
					if quote == '"' && !strings.ContainsRune("$`\"\\", rune(word[pos+1])) {
						out.WriteByte(ch)
						pos++
						continue
					}
					pos++
					out.WriteByte(word[pos])
					pos++
					continue
				}
				out.WriteByte(ch)
				pos++
			}
			if !closed {
				return "", false, false
			}
		case '\\':
			if pos+1 >= len(word) || word[pos+1] == '\n' {
				return "", false, false
			}
			pos++
			out.WriteByte(word[pos])
			pos++
		case ' ', '\t', '\r', '\n', '$', '`', '|', '&', ';', '<', '>', '(', ')', '{', '}', '~':
			return "", false, false
		case '*', '?', '[':
			hasUnquotedGlob = true
			out.WriteByte(word[pos])
			pos++
		default:
			out.WriteByte(word[pos])
			pos++
		}
	}
	return out.String(), hasUnquotedGlob, true
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

// Package statusbar provides the small local status line used by interactive
// terminal sessions. It never writes bytes to the remote connection.
package statusbar

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/parser"
	"golang.org/x/term"
)

const (
	ModeAuto = "auto"
	ModeOn   = "on"
	ModeOff  = "off"

	FullscreenHide = "hide"
	FullscreenShow = "show"

	ThemeTerminal = "terminal"
	ThemeDark     = "dark"
	ThemeLight    = "light"
	ThemeMono     = "mono"
	minimumWidth  = 20
)

// Layout controls which widgets appear in each status-bar region.
type Layout struct {
	Left   []string
	Center []string
	Right  []string
}

// Colors optionally override colors supplied by a theme. Values are validated
// configuration inputs: ANSI color names, "default", or #RRGGBB.
type Colors struct {
	Foreground string
	Background string
	Accent     string
	Warning    string
	Error      string
}

// Options are deliberately small: the renderer only needs terminal
// capability, an output stream, and the configured notice duration.
type Options struct {
	Mode           string
	Fullscreen     string
	Theme          string
	Privacy        bool
	TerminalTitle  bool
	Colors         Colors
	NoticeDuration time.Duration
	Layout         Layout
	Output         *os.File
	Input          *os.File
	Term           string
	IsTerminal     func(int) bool
	GetSize        func(int) (int, int, error)
	// ViewportChanged is called when alternate-screen suspension changes the
	// number of rows available to the remote PTY.
	ViewportChanged func(cols, rows uint16)
}

// Bar serializes remote output with local redraws. It is also an io.Writer so
// session can give it sole ownership of stdout for the attached session.
type Bar struct {
	mu              sync.Mutex
	out             io.Writer
	serializedOut   io.Writer
	outputFD        int
	eligible        bool
	enabled         bool
	suspended       bool
	alternate       bool
	closed          bool
	lastRows        int
	scrollRows      int
	scrollDirty     bool
	noticeDuration  time.Duration
	project         string
	session         string
	connection      string
	credits         string
	storage         string
	configSync      string
	layout          Layout
	notice          string
	noticeUntil     time.Time
	loading         bool
	spinner         int
	failures        map[string]failure
	failureOrder    uint64
	timer           *time.Timer
	spinnerTimer    *time.Timer
	parser          *ansi.Parser
	ansiState       byte
	appCursorSaved  bool
	appInverse      bool
	appSGR          []byte
	appSGROverflow  bool
	synchronized    bool
	redrawPending   bool
	isTerminal      func(int) bool
	getSize         func(int) (int, int, error)
	viewportChanged func(cols, rows uint16)
	fullscreen      string
	theme           string
	privacy         bool
	colors          Colors
	noColor         bool
	terminalTitle   bool
	titlePushed     bool
	remoteWrites    chan outputWrite
	redraw          chan struct{}
	ownerStop       chan struct{}
	ownerDone       chan struct{}
	ownerStopOnce   sync.Once
}

type outputWrite struct {
	data   []byte
	result chan outputResult
}
type outputResult struct {
	n   int
	err error
}

type serializedWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *serializedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(p)
}

type failure struct {
	message string
	order   uint64
}

// New returns a bar which may be disabled when the local terminal cannot
// safely support cursor-addressed output. Mode on still respects capability
// checks, rather than corrupting redirected or dumb terminals.
func New(options Options) *Bar {
	output := options.Output
	if output == nil {
		output = os.Stdout
	}
	input := options.Input
	if input == nil {
		input = os.Stdin
	}
	isTerminal := options.IsTerminal
	if isTerminal == nil {
		isTerminal = term.IsTerminal
	}
	getSize := options.GetSize
	if getSize == nil {
		getSize = term.GetSize
	}
	mode := strings.ToLower(strings.TrimSpace(options.Mode))
	if mode == "" {
		mode = ModeAuto
	}
	compatibleTerm := strings.TrimSpace(options.Term)
	if compatibleTerm == "" {
		compatibleTerm = os.Getenv("TERM")
	}
	eligible := mode != ModeOff && !strings.EqualFold(compatibleTerm, "dumb") && compatibleTerm != "" &&
		isTerminal(int(input.Fd())) && isTerminal(int(output.Fd()))
	if options.NoticeDuration <= 0 {
		options.NoticeDuration = 5 * time.Second
	}
	serializedOut := &serializedWriter{out: output}
	b := &Bar{
		out:             output,
		serializedOut:   serializedOut,
		outputFD:        int(output.Fd()),
		eligible:        eligible,
		noticeDuration:  options.NoticeDuration,
		connection:      "connecting",
		failures:        make(map[string]failure),
		parser:          ansi.NewParser(),
		ansiState:       byte(parser.GroundState),
		scrollDirty:     true,
		isTerminal:      isTerminal,
		getSize:         getSize,
		layout:          normalizeLayout(options.Layout),
		viewportChanged: options.ViewportChanged,
		fullscreen:      normalized(options.Fullscreen, FullscreenHide),
		theme:           normalized(options.Theme, ThemeTerminal),
		privacy:         options.Privacy,
		colors:          options.Colors,
		noColor:         os.Getenv("NO_COLOR") != "",
		terminalTitle:   options.TerminalTitle,
		remoteWrites:    make(chan outputWrite, 64),
		redraw:          make(chan struct{}, 1),
		ownerStop:       make(chan struct{}),
		ownerDone:       make(chan struct{}),
	}
	b.mu.Lock()
	b.refreshViewportLocked()
	b.drawNowLocked()
	b.mu.Unlock()
	go b.runOutputOwner()
	return b
}

func (b *Bar) runOutputOwner() {
	defer close(b.ownerDone)
	var redrawTimer *time.Timer
	var redrawC <-chan time.Time
	for {
		select {
		case request := <-b.remoteWrites:
			n, err := b.serializedOut.Write(request.data)
			if n > 0 {
				b.mu.Lock()
				invalidated := b.consumeANSI(request.data[:n])
				if !b.closed && b.ansiState == byte(parser.GroundState) && (invalidated || b.redrawPending) {
					b.drawLocked()
				}
				b.mu.Unlock()
			}
			request.result <- outputResult{n: n, err: err}
			continue
		default:
		}
		select {
		case request := <-b.remoteWrites:
			n, err := b.serializedOut.Write(request.data)
			if n > 0 {
				b.mu.Lock()
				invalidated := b.consumeANSI(request.data[:n])
				if !b.closed && b.ansiState == byte(parser.GroundState) && (invalidated || b.redrawPending) {
					b.drawLocked()
				}
				b.mu.Unlock()
			}
			request.result <- outputResult{n: n, err: err}
		case <-b.redraw:
			if redrawTimer == nil {
				redrawTimer = time.NewTimer(time.Second / 60)
				redrawC = redrawTimer.C
			}
		case <-redrawC:
			redrawTimer = nil
			redrawC = nil
			b.mu.Lock()
			if !b.closed {
				b.drawNowLocked()
			}
			b.mu.Unlock()
		case <-b.ownerStop:
			return
		}
	}
}

func normalized(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func normalizeLayout(layout Layout) Layout {
	if layout.Left == nil {
		layout.Left = []string{"project", "session"}
	}
	if layout.Center == nil {
		layout.Center = []string{"activity"}
	}
	if layout.Right == nil {
		layout.Right = []string{"credits", "connection"}
	}
	return Layout{Left: normalizeWidgets(layout.Left), Center: normalizeWidgets(layout.Center), Right: normalizeWidgets(layout.Right)}
}

func normalizeWidgets(widgets []string) []string {
	result := make([]string, 0, len(widgets))
	for _, widget := range widgets {
		widget = strings.ToLower(strings.TrimSpace(widget))
		if widget != "" {
			result = append(result, widget)
		}
	}
	return result
}

func (b *Bar) Enabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.refreshViewportLocked()
	return b.enabled
}

// RemoteSize returns the physical terminal size minus the local status row
// when the bar is currently active. It is safe to call for initial attaches
// and every SIGWINCH.
func (b *Bar) RemoteSize() (cols, rows uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, 0
	}
	wasEnabled, wasRows := b.enabled, b.lastRows
	w, h := b.refreshViewportLocked()
	if w <= 0 || h <= 0 {
		return 0, 0
	}
	if b.activeLocked() && (!wasEnabled || wasRows != h) {
		b.drawLocked()
	}
	if b.activeLocked() {
		h--
	}
	return clamp(w, 1000), clamp(h, 500)
}

// PrepareRemoteViewport positions the local cursor inside the reserved
// scrolling region before the first remote byte arrives. It is intentionally
// called only after an attach succeeds; connection-progress rendering should
// leave the user's existing shell cursor alone.
func (b *Bar) PrepareRemoteViewport() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	_, h := b.refreshViewportLocked()
	if !b.activeLocked() || h < 2 {
		return
	}
	b.ensureScrollRegionLocked(h - 1)
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b[%d;1H", h-1)
}

// ClearRemoteViewport starts an attached session on a clean local screen while
// preserving the reserved status row.
func (b *Bar) ClearRemoteViewport() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	_, _ = fmt.Fprint(b.serializedOut, "\x1b[2J\x1b[H")
	_, h := b.refreshViewportLocked()
	if !b.activeLocked() || h < 2 {
		return
	}
	b.ensureScrollRegionLocked(h - 1)
	b.drawLocked()
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b[%d;1H", h-1)
}

// ClearForExit restores the full viewport and leaves the host terminal at a
// clean home position after the remote shell exits normally.
func (b *Bar) ClearForExit() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.stopSpinnerLocked()
	b.scrollRows = 0
	b.scrollDirty = true
	b.enabled = false
	b.closed = true
	_, _ = fmt.Fprint(b.serializedOut, "\x1b[r\x1b[2J\x1b[H")
	b.restoreTitleLocked()
}

func clamp(value, max int) uint16 {
	if value <= 0 {
		return 0
	}
	if value > max {
		value = max
	}
	return uint16(value)
}

func (b *Bar) SetIdentity(project, session string) {
	b.mu.Lock()
	b.project = safeLabel(project)
	b.session = safeLabel(session)
	b.updateTitleLocked()
	b.drawLocked()
	b.mu.Unlock()
}

// SetViewportChanged installs the live PTY resize callback after the remote
// connection has been established.
func (b *Bar) SetViewportChanged(callback func(cols, rows uint16)) {
	b.mu.Lock()
	b.viewportChanged = callback
	b.mu.Unlock()
}

func (b *Bar) updateTitleLocked() {
	if !b.terminalTitle || b.closed {
		return
	}
	if !b.titlePushed {
		_, _ = fmt.Fprint(b.serializedOut, "\x1b[22;0t")
		b.titlePushed = true
	}
	project, session, _ := b.identityLocked()
	if b.privacy {
		project, session = "private", "session"
	}
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b]0;Paperboat - %s / %s\x07", project, session)
}

func (b *Bar) restoreTitleLocked() {
	if b.titlePushed {
		_, _ = fmt.Fprint(b.serializedOut, "\x1b[23;0t")
		b.titlePushed = false
	}
}

func (b *Bar) SetConnection(state string) {
	b.mu.Lock()
	b.connection = safeLabel(state)
	b.drawLocked()
	b.mu.Unlock()
}

// SetUsage updates the account-level values exposed by the credits and
// storage widgets. Values are server-authoritative and already display-safe.
func (b *Bar) SetUsage(credits, storage string) {
	b.mu.Lock()
	b.credits = safeLabel(credits)
	b.storage = safeLabel(storage)
	b.drawLocked()
	b.mu.Unlock()
}

// SetConfigSync updates the persistent config_sync widget without exposing
// server error details or synced paths.
func (b *Bar) SetConfigSync(state string) {
	b.mu.Lock()
	b.configSync = safeLabel(state)
	b.drawLocked()
	b.mu.Unlock()
}

// Text returns the current printable status text. It is useful for terminal
// integrations that need to observe status without inspecting ANSI output.
func (b *Bar) Text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.textLocked()
}

// Render returns the current full-width bar text without writing terminal
// control sequences. It is useful to integrations that need to observe the
// configured widget layout.
func (b *Bar) Render(width int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.layoutLocked(width)
}

// Notice temporarily replaces the identity line. Failures take precedence so
// they remain visible until the responsible lifecycle reports recovery.
func (b *Bar) Notice(message string) {
	b.mu.Lock()
	b.notice = safeLabel(message)
	b.noticeUntil = time.Now().Add(b.noticeDuration)
	b.loading = false
	b.stopSpinnerLocked()
	b.resetTimerLocked()
	b.drawLocked()
	b.mu.Unlock()
}

// Loading temporarily replaces the center region with an ASCII spinner and
// message. It is used only for work that is actively progressing.
func (b *Bar) Loading(message string) {
	b.mu.Lock()
	b.notice = safeLabel(message)
	b.noticeUntil = time.Now().Add(b.noticeDuration)
	b.loading = true
	b.resetTimerLocked()
	b.startSpinnerLocked()
	b.drawLocked()
	b.mu.Unlock()
}

func (b *Bar) Failure(message string) {
	b.FailureFor("general", message)
}

// FailureFor keeps an error visible until the same lifecycle source recovers.
func (b *Bar) FailureFor(source, message string) {
	b.mu.Lock()
	b.failureOrder++
	b.failures[safeLabel(source)] = failure{message: safeLabel(message), order: b.failureOrder}
	b.loading = false
	b.stopSpinnerLocked()
	b.drawLocked()
	b.mu.Unlock()
}

func (b *Bar) RecoverFailure() {
	b.RecoverFailureFor("general")
}

func (b *Bar) RecoverFailureFor(source string) {
	b.mu.Lock()
	delete(b.failures, safeLabel(source))
	b.drawLocked()
	b.mu.Unlock()
}

func (b *Bar) resetTimerLocked() {
	if b.timer != nil {
		b.timer.Stop()
	}
	delay := time.Until(b.noticeUntil)
	if delay <= 0 {
		delay = time.Millisecond
	}
	b.timer = time.AfterFunc(delay, func() {
		b.mu.Lock()
		if !b.noticeUntil.After(time.Now()) {
			b.notice = ""
			b.loading = false
			b.stopSpinnerLocked()
			b.drawLocked()
		}
		b.mu.Unlock()
	})
}

func (b *Bar) startSpinnerLocked() {
	if !b.loading || b.closed || b.spinnerTimer != nil {
		return
	}
	b.spinnerTimer = time.AfterFunc(120*time.Millisecond, func() {
		b.mu.Lock()
		b.spinnerTimer = nil
		if b.loading && !b.closed && b.noticeUntil.After(time.Now()) {
			b.spinner = (b.spinner + 1) % 4
			b.drawLocked()
			b.startSpinnerLocked()
		}
		b.mu.Unlock()
	})
}

func (b *Bar) stopSpinnerLocked() {
	if b.spinnerTimer != nil {
		b.spinnerTimer.Stop()
		b.spinnerTimer = nil
	}
}

// Write streams remote bytes unchanged, then redraws only after a complete
// ANSI sequence. That prevents the cursor movement used for the local line
// from being inserted in the middle of a split escape sequence.
func (b *Bar) Write(p []byte) (int, error) {
	if !b.eligible {
		return b.out.Write(p)
	}
	request := outputWrite{data: append([]byte(nil), p...), result: make(chan outputResult, 1)}
	select {
	case b.remoteWrites <- request:
	case <-b.ownerDone:
		return 0, io.ErrClosedPipe
	}
	select {
	case result := <-request.result:
		return result.n, result.err
	case <-b.ownerDone:
		return 0, io.ErrClosedPipe
	}
}

// ResetRemoteState discards parser state that cannot safely cross a transport
// discontinuity. The reattached application will redraw after its PTY resize.
func (b *Bar) ResetRemoteState() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.parser = ansi.NewParser()
	b.ansiState = byte(parser.GroundState)
	b.appCursorSaved = false
	b.appInverse = false
	b.appSGR = nil
	b.appSGROverflow = false
	b.alternate = false
	b.suspended = false
	b.synchronized = false
	b.scrollDirty = true
	b.redrawPending = true
}

func (b *Bar) consumeANSI(data []byte) (invalidated bool) {
	if b.ansiState == byte(parser.GroundState) && !bytes.ContainsRune(data, '\x1b') {
		return false
	}
	for len(data) > 0 {
		_, _, n, state := ansi.DecodeSequence(data, b.ansiState, b.parser)
		if n <= 0 {
			return invalidated
		}
		if b.resetsScrollRegion(data[:n]) {
			b.scrollDirty = true
			invalidated = true
			if b.hardResetRestoresViewport(data[:n]) {
				b.alternate = false
				if b.suspended {
					b.suspended = false
					b.notifyViewportLocked()
				}
			}
		}
		if b.erasesStatusRow(data[:n]) {
			invalidated = true
		}
		wasSynchronized := b.synchronized
		b.trackRemoteCursorSave(data[:n])
		b.trackRemoteSGR(data[:n])
		b.trackSynchronizedOutput(data[:n])
		if b.trackAlternateScreen(data[:n]) {
			invalidated = true
		}
		if wasSynchronized && !b.synchronized {
			invalidated = true
		}
		b.ansiState = state
		data = data[n:]
	}
	return invalidated
}

func (b *Bar) hardResetRestoresViewport(sequence []byte) bool {
	return len(sequence) == 2 && sequence[0] == '\x1b' && sequence[1] == 'c'
}

func (b *Bar) trackAlternateScreen(sequence []byte) bool {
	if b.fullscreen != FullscreenHide || len(sequence) < 6 || sequence[0] != '\x1b' {
		return false
	}
	raw := string(sequence)
	if !(strings.Contains(raw, "?1049") || strings.Contains(raw, "?1047") || strings.Contains(raw, "?47")) {
		return false
	}
	entering := sequence[len(sequence)-1] == 'h'
	leaving := sequence[len(sequence)-1] == 'l'
	if (!entering && !leaving) || b.alternate == entering {
		return false
	}
	b.alternate = entering
	if entering {
		_, _ = fmt.Fprint(b.serializedOut, "\x1b[r")
		b.scrollRows = 0
		b.scrollDirty = true
		b.suspended = true
	} else {
		b.suspended = false
		b.scrollDirty = true
	}
	b.notifyViewportLocked()
	return true
}

func (b *Bar) trackSynchronizedOutput(sequence []byte) {
	switch string(sequence) {
	case "\x1b[?2026h":
		b.synchronized = true
	case "\x1b[?2026l":
		b.synchronized = false
	}
}

func (b *Bar) trackRemoteCursorSave(sequence []byte) {
	switch string(sequence) {
	case "\x1b[s":
		b.appCursorSaved = true
	case "\x1b[u":
		b.appCursorSaved = false
	}
}

func (b *Bar) trackRemoteSGR(sequence []byte) {
	if len(sequence) < 3 || !strings.HasPrefix(string(sequence), "\x1b[") || sequence[len(sequence)-1] != 'm' {
		return
	}
	params := strings.TrimSuffix(strings.TrimPrefix(string(sequence), "\x1b["), "m")
	if params == "" || params == "0" {
		b.appSGR = append(b.appSGR[:0], sequence...)
		b.appSGROverflow = false
	} else if len(b.appSGR)+len(sequence) <= 4096 {
		b.appSGR = append(b.appSGR, sequence...)
	} else {
		b.appSGROverflow = true
	}
	if params == "" {
		b.appInverse = false
		return
	}
	for _, raw := range strings.Split(params, ";") {
		switch raw {
		case "0":
			b.appInverse = false
		case "7":
			b.appInverse = true
		case "27":
			b.appInverse = false
		}
	}
}

func (b *Bar) activeLocked() bool { return b.enabled && !b.suspended }

func (b *Bar) notifyViewportLocked() {
	if b.viewportChanged == nil {
		return
	}
	w, h, err := b.getSize(b.outputFD)
	if err != nil || w <= 0 || h <= 0 {
		return
	}
	if b.activeLocked() {
		h--
	}
	b.viewportChanged(clamp(w, 1000), clamp(h, 500))
}

func (b *Bar) refreshViewportLocked() (int, int) {
	if !b.eligible {
		b.enabled = false
		w, h, err := b.getSize(b.outputFD)
		if err != nil {
			return 0, 0
		}
		return w, h
	}
	w, h, err := b.getSize(b.outputFD)
	if err != nil || w < minimumWidth || h < 2 {
		if b.enabled {
			b.clearLocked()
		}
		b.enabled = false
		return w, h
	}
	b.enabled = true
	b.lastRows = h
	return w, h
}

func (b *Bar) drawLocked() {
	b.redrawPending = true
	select {
	case b.redraw <- struct{}{}:
	default:
	}
}

func (b *Bar) drawNowLocked() {
	if b.closed {
		return
	}
	w, h := b.refreshViewportLocked()
	if !b.activeLocked() || b.ansiState != byte(parser.GroundState) || b.appCursorSaved || b.synchronized {
		b.redrawPending = true
		return
	}
	if w <= 0 || h < 2 {
		b.redrawPending = true
		return
	}
	text := b.layoutLocked(w)
	b.ensureScrollRegionLocked(h - 1)
	style, restore := b.barStyleLocked()
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b[s\x1b[%d;1H\x1b[2K%s%s%s\x1b[u", h, style, text, restore)
	b.redrawPending = false
}

func (b *Bar) flushPendingRedrawLocked() {
	if !b.redrawPending || b.ansiState != byte(parser.GroundState) || b.appCursorSaved || b.synchronized {
		return
	}
	b.closed = false
	b.drawNowLocked()
	b.closed = true
}

func (b *Bar) ensureScrollRegionLocked(rows int) {
	if rows < 1 || (!b.scrollDirty && b.scrollRows == rows) {
		return
	}
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b[s\x1b[1;%dr\x1b[u", rows)
	b.scrollRows = rows
	b.scrollDirty = false
}

func (b *Bar) textLocked() string {
	project, session, connection := b.identityLocked()
	if b.privacy {
		project, session = "private", "session"
	}
	identity := " " + project + " / " + session + " / " + connection
	if failure := b.currentFailureLocked(); failure != "" {
		return identity + " / " + failure + " "
	}
	if b.notice != "" && b.noticeUntil.After(time.Now()) {
		return " Paperboat: " + b.notice + " "
	}
	return identity + " "
}

func (b *Bar) identityLocked() (project, session, connection string) {
	project, session, connection = b.project, b.session, b.connection
	if project == "" {
		project = "project"
	}
	if session == "" {
		session = "default"
	}
	if connection == "" {
		connection = "connecting"
	}
	return project, session, connection
}

func (b *Bar) layoutLocked(width int) string {
	layout := Layout{Left: append([]string(nil), b.layout.Left...), Center: append([]string(nil), b.layout.Center...), Right: append([]string(nil), b.layout.Right...)}
	for _, disposable := range []string{"storage", "credits", "config_sync", "session", "project"} {
		left, center, right := b.layoutRegionsLocked(layout)
		if ansi.StringWidth(left)+ansi.StringWidth(center)+ansi.StringWidth(right)+4 <= width {
			break
		}
		layout.Left = withoutWidget(layout.Left, disposable)
		layout.Center = withoutWidget(layout.Center, disposable)
		layout.Right = withoutWidget(layout.Right, disposable)
	}
	left, center, right := b.layoutRegionsLocked(layout)
	left = ansi.Truncate(left, width, "")
	right = ansi.Truncate(right, width, "")
	center = ansi.Truncate(center, width, "")
	lw, rw, cw := ansi.StringWidth(left), ansi.StringWidth(right), ansi.StringWidth(center)
	if center == "" {
		return fillStatusWidth(left, "", right, width)
	}
	if lw+rw+cw+4 > width {
		compact := ansi.Truncate(joinWidgets(left, center, right), width, "")
		return compact + strings.Repeat(" ", max(0, width-ansi.StringWidth(compact)))
	}
	centerStart := (width - cw) / 2
	if centerStart < lw+2 {
		centerStart = lw + 2
	}
	rightStart := width - rw
	if centerStart+cw+2 > rightStart {
		centerStart = rightStart - cw - 2
	}
	return left + strings.Repeat(" ", centerStart-lw) + center + strings.Repeat(" ", rightStart-centerStart-cw) + right
}

func (b *Bar) layoutRegionsLocked(layout Layout) (left, center, right string) {
	left = b.regionLocked(layout.Left)
	center = b.regionLocked(layout.Center)
	right = b.regionLocked(layout.Right)
	if activity := b.activityLocked(); activity != "" && !containsWidget(layout.Left, "activity") && !containsWidget(layout.Center, "activity") && !containsWidget(layout.Right, "activity") {
		center = joinWidgets(center, activity)
	}
	return left, center, right
}

func withoutWidget(widgets []string, unwanted string) []string {
	result := widgets[:0]
	for _, widget := range widgets {
		if widget != unwanted {
			result = append(result, widget)
		}
	}
	return result
}

func (b *Bar) regionLocked(widgets []string) string {
	values := make([]string, 0, len(widgets))
	for _, widget := range widgets {
		if value := b.widgetLocked(widget); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, "  ")
}

func (b *Bar) widgetLocked(widget string) string {
	project, session, connection := b.identityLocked()
	switch widget {
	case "project":
		if b.privacy {
			return ""
		}
		return b.semanticLocked(project, "accent")
	case "session":
		if b.privacy {
			return ""
		}
		return session
	case "connection":
		semantic := "accent"
		if connection == "failed" || connection == "disconnected" {
			semantic = "error"
		} else if connection == "connecting" || connection == "reconnecting" {
			semantic = "warning"
		}
		return b.semanticLocked(connection, semantic)
	case "activity":
		return b.activityLocked()
	case "config_sync":
		if b.configSync == "" {
			return ""
		}
		return "sync " + b.configSync
	case "credits":
		if b.privacy || b.credits == "" {
			return ""
		}
		return "credits " + b.credits
	case "storage":
		if b.privacy || b.storage == "" {
			return ""
		}
		return "storage " + b.storage
	default:
		return ""
	}
}

func (b *Bar) activityLocked() string {
	if failure := b.currentFailureLocked(); failure != "" {
		return b.semanticLocked("! "+failure, "error")
	}
	if b.notice != "" && b.noticeUntil.After(time.Now()) {
		if b.loading {
			return string("|/-\\"[b.spinner]) + " " + b.notice
		}
		return b.notice
	}
	return ""
}

func (b *Bar) barStyleLocked() (style, restore string) {
	if b.noColor || b.theme == ThemeMono || (b.theme == ThemeTerminal && !b.hasColorOverridesLocked()) || b.appSGROverflow {
		restore = "\x1b[27m"
		if b.appInverse {
			restore = "\x1b[7m"
		}
		return "\x1b[7m", restore
	}
	style = b.baseStyleLocked()
	restore = "\x1b[0m" + string(b.appSGR)
	return style, restore
}

func (b *Bar) baseStyleLocked() string {
	if b.theme == ThemeTerminal {
		if b.colors.Foreground == "" && b.colors.Background == "" {
			return "\x1b[39m\x1b[49m\x1b[7m"
		}
		return colorSequence(firstNonEmpty(b.colors.Foreground, "default"), false) + colorSequence(firstNonEmpty(b.colors.Background, "default"), true)
	}
	foreground, background := "bright_white", "black"
	if b.theme == ThemeLight {
		foreground, background = "black", "bright_white"
	}
	if b.colors.Foreground != "" {
		foreground = b.colors.Foreground
	}
	if b.colors.Background != "" {
		background = b.colors.Background
	}
	return colorSequence(foreground, false) + colorSequence(background, true)
}

func (b *Bar) semanticLocked(value, semantic string) string {
	if value == "" || b.noColor || b.theme == ThemeMono || (b.theme == ThemeTerminal && !b.hasColorOverridesLocked()) {
		return value
	}
	color := ""
	switch semantic {
	case "accent":
		color = firstNonEmpty(b.colors.Accent, "bright_cyan")
	case "warning":
		color = firstNonEmpty(b.colors.Warning, "bright_yellow")
	case "error":
		color = firstNonEmpty(b.colors.Error, "bright_red")
	}
	if color == "" {
		return value
	}
	return colorSequence(color, false) + value + b.baseStyleLocked()
}

func (b *Bar) hasColorOverridesLocked() bool {
	return b.colors.Foreground != "" || b.colors.Background != "" || b.colors.Accent != "" || b.colors.Warning != "" || b.colors.Error != ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func colorSequence(value string, background bool) string {
	value = strings.ToLower(strings.TrimSpace(value))
	base := 30
	if background {
		base = 40
	}
	if value == "" || value == "default" {
		if background {
			return "\x1b[49m"
		}
		return "\x1b[39m"
	}
	if strings.HasPrefix(value, "#") && len(value) == 7 {
		r, _ := strconv.ParseUint(value[1:3], 16, 8)
		g, _ := strconv.ParseUint(value[3:5], 16, 8)
		bl, _ := strconv.ParseUint(value[5:7], 16, 8)
		prefix := 38
		if background {
			prefix = 48
		}
		return fmt.Sprintf("\x1b[%d;2;%d;%d;%dm", prefix, r, g, bl)
	}
	names := []string{"black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"}
	bright := strings.HasPrefix(value, "bright_")
	value = strings.TrimPrefix(value, "bright_")
	for index, name := range names {
		if value == name {
			if bright {
				base += 60
			}
			return fmt.Sprintf("\x1b[%dm", base+index)
		}
	}
	return ""
}

func containsWidget(widgets []string, wanted string) bool {
	for _, widget := range widgets {
		if widget == wanted {
			return true
		}
	}
	return false
}

func joinWidgets(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			values = append(values, part)
		}
	}
	return strings.Join(values, "  ")
}

func fillStatusWidth(left, center, right string, width int) string {
	content := left
	if center != "" {
		content += " | " + center
	}
	content = ansi.Truncate(content, max(0, width-ansi.StringWidth(right)), "")
	padding := width - ansi.StringWidth(content) - ansi.StringWidth(right)
	if padding < 1 && right != "" {
		content = ansi.Truncate(content, max(0, width-ansi.StringWidth(right)-1), "")
		padding = 1
	}
	return content + strings.Repeat(" ", max(0, padding)) + right
}

func (b *Bar) currentFailureLocked() string {
	var current failure
	for _, candidate := range b.failures {
		if candidate.order > current.order {
			current = candidate
		}
	}
	return current.message
}

func (b *Bar) clearLocked() {
	if b.lastRows < 1 {
		return
	}
	_, _ = fmt.Fprintf(b.serializedOut, "\x1b[s\x1b[%d;1H\x1b[2K\x1b[r\x1b[u", b.lastRows)
	b.scrollRows = 0
	b.scrollDirty = true
}

func (b *Bar) resetsScrollRegion(sequence []byte) bool {
	if len(sequence) == 0 {
		return false
	}
	// DECSTBM, RIS, and alternate-screen swaps can reset the physical scroll
	// margins. Reapply our local margin after the remote sequence is complete.
	if len(sequence) == 2 && sequence[0] == '\x1b' && sequence[1] == 'c' {
		return true
	}
	if !strings.HasPrefix(string(sequence), "\x1b[") {
		return false
	}
	last := sequence[len(sequence)-1]
	if last == 'r' {
		return true
	}
	return (last == 'h' || last == 'l') && bytes.Contains(sequence, []byte("?1049"))
}

func (b *Bar) erasesStatusRow(sequence []byte) bool {
	if len(sequence) < 3 || !bytes.HasPrefix(sequence, []byte("\x1b[")) {
		return false
	}
	// ED can erase outside the remote scroll region, including the status row.
	return sequence[len(sequence)-1] == 'J'
}

// Close clears the reserved row. It is safe to call more than once.
func (b *Bar) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		b.ownerStopOnce.Do(func() { close(b.ownerStop) })
		<-b.ownerDone
		return nil
	}
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.stopSpinnerLocked()
	b.enabled = false
	b.closed = true
	b.mu.Unlock()
	b.ownerStopOnce.Do(func() { close(b.ownerStop) })
	<-b.ownerDone
	b.mu.Lock()
	b.flushPendingRedrawLocked()
	b.clearLocked()
	b.restoreTitleLocked()
	b.enabled = false
	b.mu.Unlock()
	return nil
}

func safeLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var out strings.Builder
	for _, r := range value {
		if !unicode.IsGraphic(r) || r == '\x1b' || r == '/' || r == '\\' {
			out.WriteRune(' ')
			continue
		}
		out.WriteRune(r)
		if out.Len() >= 80 {
			break
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

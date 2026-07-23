// Package statusbar provides the small local status line used by interactive
// terminal sessions. It never writes bytes to the remote connection.
package statusbar

import (
	"bytes"
	"fmt"
	"io"
	"os"
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
)

// Layout controls which widgets appear in each status-bar region.
type Layout struct {
	Left   []string
	Center []string
	Right  []string
}

// Options are deliberately small: the renderer only needs terminal
// capability, an output stream, and the configured notice duration.
type Options struct {
	Mode           string
	NoticeDuration time.Duration
	Layout         Layout
	Output         *os.File
	Input          *os.File
	Term           string
	IsTerminal     func(int) bool
	GetSize        func(int) (int, int, error)
}

// Bar serializes remote output with local redraws. It is also an io.Writer so
// session can give it sole ownership of stdout for the attached session.
type Bar struct {
	mu             sync.Mutex
	out            io.Writer
	outputFD       int
	eligible       bool
	enabled        bool
	closed         bool
	lastRows       int
	scrollRows     int
	scrollDirty    bool
	noticeDuration time.Duration
	project        string
	session        string
	connection     string
	credits        string
	storage        string
	configSync     string
	layout         Layout
	notice         string
	noticeUntil    time.Time
	loading        bool
	spinner        int
	failures       map[string]failure
	failureOrder   uint64
	timer          *time.Timer
	spinnerTimer   *time.Timer
	parser         *ansi.Parser
	ansiState      byte
	appCursorSaved bool
	appInverse     bool
	synchronized   bool
	isTerminal     func(int) bool
	getSize        func(int) (int, int, error)
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
	b := &Bar{
		out:            output,
		outputFD:       int(output.Fd()),
		eligible:       eligible,
		noticeDuration: options.NoticeDuration,
		connection:     "connecting",
		failures:       make(map[string]failure),
		parser:         ansi.NewParser(),
		ansiState:      byte(parser.GroundState),
		scrollDirty:    true,
		isTerminal:     isTerminal,
		getSize:        getSize,
		layout:         normalizeLayout(options.Layout),
	}
	b.mu.Lock()
	b.refreshViewportLocked()
	b.drawLocked()
	b.mu.Unlock()
	return b
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
	if b.enabled && (!wasEnabled || wasRows != h) {
		b.drawLocked()
	}
	if b.enabled {
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
	if !b.enabled || h < 2 {
		return
	}
	b.ensureScrollRegionLocked(h - 1)
	_, _ = fmt.Fprintf(b.out, "\x1b[%d;1H", h-1)
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
	b.drawLocked()
	b.mu.Unlock()
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
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.out.Write(p)
	if n > 0 {
		b.consumeANSI(p[:n])
		if !b.closed && b.ansiState == byte(parser.GroundState) {
			b.drawLocked()
		}
	}
	return n, err
}

func (b *Bar) consumeANSI(data []byte) {
	for len(data) > 0 {
		_, _, n, state := ansi.DecodeSequence(data, b.ansiState, b.parser)
		if n <= 0 {
			return
		}
		if b.resetsScrollRegion(data[:n]) {
			b.scrollDirty = true
		}
		b.trackRemoteCursorSave(data[:n])
		b.trackRemoteSGR(data[:n])
		b.trackSynchronizedOutput(data[:n])
		b.ansiState = state
		data = data[n:]
	}
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
	if err != nil || w <= 0 || h < 2 {
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
	if b.closed {
		return
	}
	b.refreshViewportLocked()
	if !b.enabled || b.ansiState != byte(parser.GroundState) || b.appCursorSaved || b.synchronized {
		return
	}
	w, h, err := b.getSize(b.outputFD)
	if err != nil || w <= 0 || h < 2 {
		return
	}
	text := b.layoutLocked(w)
	b.ensureScrollRegionLocked(h - 1)
	// CSI s/u avoids DEC's saved-cursor slot, which full-screen applications
	// commonly use. Reverse-video is restored with SGR 7/27 only, preserving
	// the application's colors and other active SGR attributes.
	restoreInverse := "\x1b[27m"
	if b.appInverse {
		restoreInverse = "\x1b[7m"
	}
	_, _ = fmt.Fprintf(b.out, "\x1b[s\x1b[%d;1H\x1b[2K\x1b[7m%s%s\x1b[u", h, text, restoreInverse)
}

func (b *Bar) ensureScrollRegionLocked(rows int) {
	if rows < 1 || (!b.scrollDirty && b.scrollRows == rows) {
		return
	}
	_, _ = fmt.Fprintf(b.out, "\x1b[s\x1b[1;%dr\x1b[u", rows)
	b.scrollRows = rows
	b.scrollDirty = false
}

func (b *Bar) textLocked() string {
	project, session, connection := b.identityLocked()
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
	left := b.regionLocked(b.layout.Left)
	center := b.regionLocked(b.layout.Center)
	right := b.regionLocked(b.layout.Right)
	if activity := b.activityLocked(); activity != "" && !containsWidget(b.layout.Left, "activity") && !containsWidget(b.layout.Center, "activity") && !containsWidget(b.layout.Right, "activity") {
		center = joinWidgets(center, activity)
	}
	left = ansi.Truncate(left, width, "")
	right = ansi.Truncate(right, width, "")
	center = ansi.Truncate(center, width, "")
	lw, rw, cw := ansi.StringWidth(left), ansi.StringWidth(right), ansi.StringWidth(center)
	if center == "" {
		return fillStatusWidth(left, "", right, width)
	}
	if lw+rw+cw+4 > width {
		compact := ansi.Truncate(left+" | "+center+" | "+right, width, "")
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
		return project
	case "session":
		return session
	case "connection":
		return connection
	case "activity":
		return b.activityLocked()
	case "config_sync":
		if b.configSync == "" {
			return ""
		}
		return "sync " + b.configSync
	case "credits":
		if b.credits == "" {
			return ""
		}
		return "credits " + b.credits
	case "storage":
		if b.storage == "" {
			return ""
		}
		return "storage " + b.storage
	default:
		return ""
	}
}

func (b *Bar) activityLocked() string {
	if failure := b.currentFailureLocked(); failure != "" {
		return "! " + failure
	}
	if b.notice != "" && b.noticeUntil.After(time.Now()) {
		if b.loading {
			return string("|/-\\"[b.spinner]) + " " + b.notice
		}
		return b.notice
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
	_, _ = fmt.Fprintf(b.out, "\x1b[s\x1b[%d;1H\x1b[2K\x1b[r\x1b[u", b.lastRows)
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

// Close clears the reserved row. It is safe to call more than once.
func (b *Bar) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.stopSpinnerLocked()
	b.clearLocked()
	b.enabled = false
	b.closed = true
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

package statusbar

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/ansi/parser"
)

func newTestBar(t *testing.T, mode, terminal string, width, height int, terminalOK bool, notice time.Duration) (*Bar, *os.File) {
	t.Helper()
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	reader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = output.Close() })
	bar := New(Options{
		Mode:           mode,
		Term:           terminal,
		NoticeDuration: notice,
		Input:          input,
		Output:         output,
		IsTerminal:     func(int) bool { return terminalOK },
		GetSize: func(int) (int, int, error) {
			return width, height, nil
		},
	})
	return bar, reader
}

func textOf(t *testing.T, bar *Bar) string {
	t.Helper()
	bar.mu.Lock()
	defer bar.mu.Unlock()
	return bar.textLocked()
}

func TestIdentityNoticeAndStickyRecovery(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, 15*time.Millisecond)
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")
	if got := textOf(t, bar); got != " demo / default / connected " {
		t.Fatalf("identity = %q", got)
	}
	bar.Notice("Uploading image")
	if got := textOf(t, bar); !strings.Contains(got, "Uploading image") {
		t.Fatalf("notice = %q", got)
	}
	time.Sleep(40 * time.Millisecond)
	if got := textOf(t, bar); got != " demo / default / connected " {
		t.Fatalf("expired notice = %q", got)
	}
	bar.FailureFor("upload", "Image upload failed")
	bar.FailureFor("sync", "Config sync failed")
	bar.RecoverFailureFor("upload")
	if got := textOf(t, bar); !strings.Contains(got, "Config sync failed") {
		t.Fatalf("unrelated recovery cleared failure: %q", got)
	}
	bar.RecoverFailureFor("sync")
	if got := textOf(t, bar); got != " demo / default / connected " {
		t.Fatalf("recovered status = %q", got)
	}
}

func TestPersistentLoadingSurvivesNoticeTimeout(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, 15*time.Millisecond)
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")
	bar.LoadingPersistent("Uploading file")
	time.Sleep(40 * time.Millisecond)
	if got := textOf(t, bar); !strings.Contains(got, "Uploading file") {
		t.Fatalf("persistent loading expired: %q", got)
	}
	bar.Notice("File uploaded")
	if got := textOf(t, bar); !strings.Contains(got, "File uploaded") {
		t.Fatalf("completion did not replace loading: %q", got)
	}
	time.Sleep(40 * time.Millisecond)
	if got := textOf(t, bar); got != " demo / default / connected " {
		t.Fatalf("completion notice did not expire: %q", got)
	}
}

func TestLayoutAnchorsIdentityActivityAndConnection(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, time.Second)
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")
	bar.Loading("Uploading image")
	bar.mu.Lock()
	line := bar.layoutLocked(80)
	bar.mu.Unlock()
	if !strings.HasPrefix(line, "demo  default") || !strings.HasSuffix(line, "connected") {
		t.Fatalf("anchored layout = %q", line)
	}
	if !strings.Contains(line, "Uploading image") || !strings.Contains(line, "| Uploading image") {
		t.Fatalf("spinner activity missing from layout = %q", line)
	}
	if got := ansi.StringWidth(line); got != 80 {
		t.Fatalf("layout width = %d, want 80", got)
	}
}

func TestTransportIndicatorIsAlwaysLast(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, time.Second)
	bar.layout = Layout{Left: []string{"project"}, Center: []string{}, Right: []string{"connection"}}
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")

	bar.SetTransport("quic")
	if line := bar.Render(80); !strings.HasSuffix(line, "connected  Q") {
		t.Fatalf("QUIC indicator is not last: %q", line)
	}
	bar.SetTransport("wss")
	if line := bar.Render(80); !strings.HasSuffix(line, "connected  W") {
		t.Fatalf("WSS indicator is not last: %q", line)
	}
	bar.SetTransport("unknown")
	if line := bar.Render(80); !strings.HasSuffix(line, "connected") {
		t.Fatalf("unknown transport should be hidden: %q", line)
	}
}

func TestLayoutUsesConfiguredRegionsAndAccountWidgets(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 96, 24, true, time.Second)
	bar.layout = Layout{
		Left:   []string{"credits", "project"},
		Center: []string{"storage", "activity"},
		Right:  []string{"config_sync", "connection"},
	}
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")
	bar.SetUsage("100", "12 GB")
	bar.SetConfigSync("healthy")
	bar.Loading("Uploading image")
	bar.mu.Lock()
	line := bar.layoutLocked(96)
	bar.mu.Unlock()
	if !strings.HasPrefix(line, "credits 100  demo") {
		t.Fatalf("left layout = %q", line)
	}
	if !strings.Contains(line, "storage 12 GB") || !strings.Contains(line, "| Uploading image") {
		t.Fatalf("center layout = %q", line)
	}
	if !strings.HasSuffix(line, "sync healthy  connected") {
		t.Fatalf("right layout = %q", line)
	}
	if got := ansi.StringWidth(line); got != 96 {
		t.Fatalf("layout width = %d, want 96", got)
	}
}

func TestResponsiveLayoutKeepsConnectionAndDropsUsageFirst(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 30, 24, true, time.Second)
	bar.layout = Layout{Left: []string{"project", "session"}, Center: []string{"activity"}, Right: []string{"storage", "credits", "connection"}}
	bar.SetIdentity("long-project", "default")
	bar.SetUsage("1000", "999 GB")
	bar.SetConnection("reconnecting")
	line := bar.Render(30)
	if !strings.Contains(line, "reconnecting") || strings.Contains(line, "storage") || strings.Contains(line, "credits") {
		t.Fatalf("responsive layout = %q", line)
	}
	if ansi.StringWidth(line) != 30 {
		t.Fatalf("responsive width = %d", ansi.StringWidth(line))
	}
}

func TestLayoutAllowsExplicitlyEmptyRegions(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 30, 24, true, time.Second)
	bar.layout = Layout{Left: []string{}, Center: []string{}, Right: []string{"connection"}}
	bar.SetConnection("connected")
	bar.mu.Lock()
	line := bar.layoutLocked(30)
	bar.mu.Unlock()
	if !strings.HasSuffix(line, "connected") || ansi.StringWidth(line) != 30 {
		t.Fatalf("empty-region layout = %q", line)
	}
}

func TestFullscreenHideReleasesAndReacquiresRemoteRow(t *testing.T) {
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer output.Close()
	var sizes [][2]uint16
	bar := New(Options{
		Mode: ModeAuto, Fullscreen: FullscreenHide, Term: "xterm-256color", Input: input, Output: output,
		IsTerminal: func(int) bool { return true }, GetSize: func(int) (int, int, error) { return 80, 24, nil },
		ViewportChanged: func(cols, rows uint16) { sizes = append(sizes, [2]uint16{cols, rows}) },
	})
	if _, rows := bar.RemoteSize(); rows != 23 {
		t.Fatalf("initial rows = %d", rows)
	}
	_, _ = bar.Write([]byte("\x1b[?1049h"))
	if _, rows := bar.RemoteSize(); rows != 24 || !bar.suspended {
		t.Fatalf("fullscreen rows = %d suspended=%t", rows, bar.suspended)
	}
	_, _ = bar.Write([]byte("\x1bc"))
	if _, rows := bar.RemoteSize(); rows != 23 || bar.suspended || bar.alternate {
		t.Fatalf("hard-reset rows = %d suspended=%t alternate=%t", rows, bar.suspended, bar.alternate)
	}
	_, _ = bar.Write([]byte("\x1b[?1049h"))
	_, _ = bar.Write([]byte("\x1b[?1049l"))
	if _, rows := bar.RemoteSize(); rows != 23 || bar.suspended {
		t.Fatalf("restored rows = %d suspended=%t", rows, bar.suspended)
	}
	if len(sizes) != 4 || sizes[0] != [2]uint16{80, 24} || sizes[1] != [2]uint16{80, 23} || sizes[2] != [2]uint16{80, 24} || sizes[3] != [2]uint16{80, 23} {
		t.Fatalf("viewport notifications = %#v", sizes)
	}
}

func TestFullscreenShowKeepsReservedRow(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, time.Second)
	bar.fullscreen = FullscreenShow
	_, _ = bar.Write([]byte("\x1b[?1049h"))
	if _, rows := bar.RemoteSize(); rows != 23 || bar.suspended {
		t.Fatalf("rows = %d suspended=%t", rows, bar.suspended)
	}
}

func TestThemePrivacyAndSemanticColors(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	input, _, _ := os.Pipe()
	reader, output, _ := os.Pipe()
	defer input.Close()
	defer reader.Close()
	defer output.Close()
	bar := New(Options{
		Mode: ModeAuto, Theme: ThemeDark, Privacy: true, Colors: Colors{Accent: "#00ff88"}, Term: "xterm", Input: input, Output: output,
		IsTerminal: func(int) bool { return true }, GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	bar.SetIdentity("secret-project", "secret-session")
	bar.SetUsage("100", "12 GB")
	bar.SetConnection("connected")
	line := bar.Render(80)
	if strings.Contains(line, "secret") || strings.Contains(line, "credits") || strings.Contains(line, "storage") {
		t.Fatalf("privacy leaked data: %q", line)
	}
	if !strings.Contains(line, "\x1b[") || ansi.StringWidth(line) != 80 {
		t.Fatalf("themed line = %q width=%d", line, ansi.StringWidth(line))
	}
}

func TestTerminalTitleIsPushedAndRestored(t *testing.T) {
	input, _, _ := os.Pipe()
	reader, output, _ := os.Pipe()
	defer input.Close()
	defer reader.Close()
	bar := New(Options{
		Mode: ModeAuto, TerminalTitle: true, Term: "xterm", Input: input, Output: output,
		IsTerminal: func(int) bool { return true }, GetSize: func(int) (int, int, error) { return 80, 24, nil },
	})
	bar.SetIdentity("demo", "default")
	_ = bar.Close()
	_ = output.Close()
	raw, _ := io.ReadAll(reader)
	if !strings.Contains(string(raw), "\x1b[22;0t\x1b]0;Paperboat - demo / default\x07") || !strings.Contains(string(raw), "\x1b[23;0t") {
		t.Fatalf("title lifecycle = %q", raw)
	}
}

func TestLoadingSpinnerAdvances(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 80, 24, true, time.Second)
	bar.Loading("Preparing connection")
	bar.mu.Lock()
	first := bar.activityLocked()
	bar.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	bar.mu.Lock()
	second := bar.activityLocked()
	bar.mu.Unlock()
	if first == second || !strings.Contains(second, "Preparing connection") {
		t.Fatalf("spinner did not advance: first=%q second=%q", first, second)
	}
	_ = bar.Close()
}

func TestWriteDefersRedrawUntilSplitANSICompletes(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	if _, err := bar.Write([]byte("\x1b[")); err != nil {
		t.Fatal(err)
	}
	if _, err := bar.Write([]byte("2Jhello")); err != nil {
		t.Fatal(err)
	}
	if _, err := bar.Write([]byte("\x1b[r")); err != nil {
		t.Fatal(err)
	}
	_ = bar.Close()
	// Close the writer so the pipe reader can collect the complete transcript.
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\x1b[3;1H"); got != 3 { // initial draw, reset redraw, cleanup
		t.Fatalf("bottom-row operations = %d, raw=%q", got, raw)
	}
	if !strings.Contains(string(raw), "\x1b[2Jhello") {
		t.Fatalf("remote output changed: %q", raw)
	}
	if got := strings.Count(string(raw), "\x1b[1;2r"); got < 2 {
		t.Fatalf("scroll region was not restored after remote reset: %q", raw)
	}
	if !strings.Contains(string(raw), "\x1b[r") {
		t.Fatalf("scroll region was not reset on cleanup: %q", raw)
	}
	if strings.Contains(string(raw), "\x1b7") || strings.Contains(string(raw), "\x1b[0m") {
		t.Fatalf("renderer changed remote DEC cursor or reset SGR state: %q", raw)
	}
	if !strings.Contains(string(raw), "\x1b[7m") || !strings.Contains(string(raw), "\x1b[27m") {
		t.Fatalf("renderer did not apply and restore its reverse-video background: %q", raw)
	}
}

func TestResetRemoteStateDiscardsPartialANSIAndSavedState(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	if _, err := bar.Write([]byte("\x1b[")); err != nil {
		t.Fatal(err)
	}
	bar.mu.Lock()
	bar.appCursorSaved = true
	bar.appInverse = true
	bar.synchronized = true
	bar.mu.Unlock()
	bar.ResetRemoteState()
	bar.mu.Lock()
	defer bar.mu.Unlock()
	if bar.ansiState != byte(parser.GroundState) || bar.appCursorSaved || bar.appInverse || bar.synchronized || !bar.scrollDirty || !bar.redrawPending {
		t.Fatalf("state was not reset: %#v", bar)
	}
}

func TestClearForExitRestoresAndClearsFullViewport(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	bar.ClearForExit()
	closeDone := make(chan struct{})
	go func() {
		_ = bar.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close blocked after ClearForExit")
	}
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\x1b[r\x1b[2J\x1b[H") || !bar.closed || bar.enabled {
		t.Fatalf("exit clear state closed=%v enabled=%v raw=%q", bar.closed, bar.enabled, raw)
	}
}

func TestPlainRemoteOutputDoesNotRedrawStatusBar(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	if _, err := bar.Write([]byte("plain remote output")); err != nil {
		t.Fatal(err)
	}
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\x1b[3;1H"); got != 2 { // initial draw and cleanup
		t.Fatalf("plain output caused status redraw: count=%d raw=%q", got, raw)
	}
}

func TestDefersRedrawWhileRemoteUsesANSICursorSave(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	if _, err := bar.Write([]byte("\x1b[s")); err != nil {
		t.Fatal(err)
	}
	bar.Notice("Uploading image")
	if _, err := bar.Write([]byte("remote output")); err != nil {
		t.Fatal(err)
	}
	if _, err := bar.Write([]byte("\x1b[u")); err != nil {
		t.Fatal(err)
	}
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\x1b[3;1H"); got != 3 { // initial draw, post-restore draw, cleanup
		t.Fatalf("unexpected redraw while remote cursor was saved: %d, raw=%q", got, raw)
	}
}

func TestDefersRedrawDuringSynchronizedOutput(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	if _, err := bar.Write([]byte("\x1b[?2026hframe-a")); err != nil {
		t.Fatal(err)
	}
	bar.Notice("Reconnected")
	if _, err := bar.Write([]byte("frame-b")); err != nil {
		t.Fatal(err)
	}
	if _, err := bar.Write([]byte("\x1b[?2026l")); err != nil {
		t.Fatal(err)
	}
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	transcript := string(raw)
	start := strings.Index(transcript, "\x1b[?2026h")
	end := strings.Index(transcript, "\x1b[?2026l")
	if start < 0 || end < start {
		t.Fatalf("missing synchronized frame: %q", transcript)
	}
	if strings.Contains(transcript[start:end], "\x1b[3;1H") {
		t.Fatalf("status bar redrew inside synchronized frame: %q", transcript[start:end])
	}
	if !strings.Contains(transcript[end+len("\x1b[?2026l"):], "\x1b[3;1H") {
		t.Fatalf("status bar did not redraw after synchronized frame: %q", transcript)
	}
}

func TestStatusUpdatesCoalesceToOneDisplayFrame(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	for i := 0; i < 100; i++ {
		bar.SetConnection("connecting")
	}
	time.Sleep(30 * time.Millisecond)
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\x1b[3;1H"); got != 3 { // initial, one coalesced frame, cleanup
		t.Fatalf("status updates rendered %d frames: %q", got, raw)
	}
}

func TestRemoteOutputPrecedesPendingStatusFrame(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	bar.Notice("pending")
	if _, err := bar.Write([]byte("REMOTE")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	transcript := string(raw)
	remote := strings.Index(transcript, "REMOTE")
	pending := strings.Index(transcript, "pending")
	if remote < 0 || pending < 0 || remote > pending {
		t.Fatalf("remote output was not prioritized: %q", transcript)
	}
}

func TestSlowOutputAppliesBoundedBackpressure(t *testing.T) {
	bar, reader := newTestBar(t, ModeAuto, "xterm-256color", 40, 3, true, time.Second)
	payload := make([]byte, 64<<10)
	const writers = 70
	var wg sync.WaitGroup
	wg.Add(writers)
	done := make(chan struct{}, writers)
	for range writers {
		go func() {
			defer wg.Done()
			_, _ = bar.Write(payload)
			done <- struct{}{}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	if completed := len(done); completed == writers {
		t.Fatal("slow stdout did not apply backpressure")
	}
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(drainDone)
	}()
	wg.Wait()
	_ = bar.Close()
	if output, ok := bar.out.(*os.File); ok {
		_ = output.Close()
	}
	<-drainDone
}

func TestTruncationAndFallbackModes(t *testing.T) {
	bar, _ := newTestBar(t, ModeAuto, "xterm-256color", 8, 2, true, time.Second)
	bar.SetIdentity("very-long-project", "default")
	bar.mu.Lock()
	line := ansi.Truncate(bar.textLocked(), 8, "")
	bar.mu.Unlock()
	if got := ansi.StringWidth(line); got > 8 {
		t.Fatalf("width = %d, line=%q", got, line)
	}
	bar.mu.Lock()
	fullWidth := ansi.Truncate(bar.textLocked(), 8, "")
	if padding := 8 - ansi.StringWidth(fullWidth); padding > 0 {
		fullWidth += strings.Repeat(" ", padding)
	}
	bar.mu.Unlock()
	if got := ansi.StringWidth(fullWidth); got != 8 {
		t.Fatalf("full-width status = %d, line=%q", got, fullWidth)
	}
	for _, tc := range []struct {
		mode, term string
		height     int
		terminalOK bool
	}{
		{ModeOff, "xterm", 24, true},
		{ModeAuto, "dumb", 24, true},
		{ModeAuto, "xterm", 1, true},
		{ModeAuto, "xterm", 24, false},
	} {
		fallback, _ := newTestBar(t, tc.mode, tc.term, 80, tc.height, tc.terminalOK, time.Second)
		if fallback.Enabled() {
			t.Fatalf("bar enabled for %+v", tc)
		}
		_, rows := fallback.RemoteSize()
		if rows != uint16(tc.height) {
			t.Fatalf("fallback rows = %d, want %d for %+v", rows, tc.height, tc)
		}
	}
}

func TestRemoteSizeRestoresAndReappliesMarginAcrossSmallResize(t *testing.T) {
	height := 4
	input, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	bar := New(Options{
		Mode:           ModeAuto,
		Term:           "xterm-256color",
		NoticeDuration: time.Second,
		Input:          input,
		Output:         output,
		IsTerminal:     func(int) bool { return true },
		GetSize: func(int) (int, int, error) {
			return 80, height, nil
		},
	})
	if cols, rows := bar.RemoteSize(); cols != 80 || rows != 3 {
		t.Fatalf("initial remote size = %dx%d, want 80x3", cols, rows)
	}
	height = 1
	if cols, rows := bar.RemoteSize(); cols != 80 || rows != 1 || bar.Enabled() {
		t.Fatalf("small terminal size = %dx%d enabled=%v", cols, rows, bar.Enabled())
	}
	height = 5
	if cols, rows := bar.RemoteSize(); cols != 80 || rows != 4 || !bar.Enabled() {
		t.Fatalf("restored remote size = %dx%d enabled=%v", cols, rows, bar.Enabled())
	}
	bar.PrepareRemoteViewport()
	_ = bar.Close()
	_ = output.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\x1b[1;4r") || !strings.Contains(string(raw), "\x1b[5;1H") || !strings.Contains(string(raw), "\x1b[4;1H") {
		t.Fatalf("status bar did not redraw after resize: %q", raw)
	}
}

func BenchmarkWritePlainRemoteOutput(b *testing.B) {
	output, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer output.Close()
	input, err := os.Open(os.DevNull)
	if err != nil {
		b.Fatal(err)
	}
	defer input.Close()
	bar := New(Options{Mode: ModeOn, Term: "xterm-256color", Input: input, Output: output, IsTerminal: func(int) bool { return true }, GetSize: func(int) (int, int, error) { return 120, 40, nil }})
	defer bar.Close()
	payload := []byte("terminal output without control sequences\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := bar.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteANSIRemoteOutput(b *testing.B) {
	output, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer output.Close()
	input, err := os.Open(os.DevNull)
	if err != nil {
		b.Fatal(err)
	}
	defer input.Close()
	bar := New(Options{Mode: ModeOn, Term: "xterm-256color", Input: input, Output: output, IsTerminal: func(int) bool { return true }, GetSize: func(int) (int, int, error) { return 120, 40, nil }})
	defer bar.Close()
	payload := []byte("\x1b[38;5;42mcolored terminal output\x1b[0m\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := bar.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

package statusbar

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
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
	if got := strings.Count(string(raw), "\x1b[3;1H"); got != 4 { // initial draw, completed sequence draw, reset redraw, cleanup
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

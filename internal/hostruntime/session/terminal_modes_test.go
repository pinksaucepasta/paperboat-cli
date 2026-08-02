package session

import "testing"

func TestTerminalModeTrackerTracksFragmentedPTYOutput(t *testing.T) {
	var tracker terminalModeTracker
	tracker.Consume([]byte("\x1b[?1049h\x1b[?100"))
	tracker.Consume([]byte("3h\x1b[?1006h\x1b[?2004h"))
	modes := tracker.Modes()
	if !modes.AlternateScreen || !modes.MouseMotion || !modes.MouseSGR || !modes.BracketedPaste {
		t.Fatalf("modes = %+v", modes)
	}
	tracker.Consume([]byte("\x1b[?1003l\x1b[?1049l"))
	modes = tracker.Modes()
	if modes.AlternateScreen || modes.MouseMotion || !modes.MouseSGR || !modes.BracketedPaste {
		t.Fatalf("modes after disable = %+v", modes)
	}
	if got, want := modes.ResumeSequence(), "\x1b[?1006h\x1b[?2004h"; got != want {
		t.Fatalf("resume = %q, want %q", got, want)
	}
	tracker.Consume([]byte("\x1bc"))
	if modes := tracker.Modes(); modes != (TerminalModes{}) {
		t.Fatalf("RIS did not reset modes: %+v", modes)
	}
}

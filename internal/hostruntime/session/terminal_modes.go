package session

import "bytes"

// TerminalModes is the subset of terminal state that must be restored when a
// new local emulator attaches to an already-running PTY. It is derived from
// PTY output; the runtime never guesses that a mode is enabled.
type TerminalModes struct {
	AlternateScreen bool `json:"alternate_screen,omitempty"`
	MouseClick      bool `json:"mouse_click,omitempty"`
	MouseDrag       bool `json:"mouse_drag,omitempty"`
	MouseMotion     bool `json:"mouse_motion,omitempty"`
	MouseURXVT      bool `json:"mouse_urxvt,omitempty"`
	MouseSGR        bool `json:"mouse_sgr,omitempty"`
	FocusEvents     bool `json:"focus_events,omitempty"`
	BracketedPaste  bool `json:"bracketed_paste,omitempty"`
}

func (m TerminalModes) ResumeSequence() string {
	var out bytes.Buffer
	for _, item := range []struct {
		on bool
		id string
	}{
		{m.AlternateScreen, "1049"}, {m.MouseClick, "1000"}, {m.MouseDrag, "1002"},
		{m.MouseMotion, "1003"}, {m.MouseURXVT, "1015"}, {m.MouseSGR, "1006"},
		{m.BracketedPaste, "2004"}, {m.FocusEvents, "1004"},
	} {
		if item.on {
			out.WriteString("\x1b[?")
			out.WriteString(item.id)
			out.WriteByte('h')
		}
	}
	return out.String()
}

type terminalModeTracker struct {
	modes TerminalModes
	tail  []byte
}

func (t *terminalModeTracker) Modes() TerminalModes { return t.modes }

func (t *terminalModeTracker) Reset() { t.modes, t.tail = TerminalModes{}, nil }

func (t *terminalModeTracker) Consume(data []byte) {
	data = append(t.tail, data...)
	t.tail = nil
	for len(data) > 0 {
		index := bytes.IndexByte(data, '\x1b')
		if index < 0 {
			return
		}
		data = data[index:]
		if len(data) == 1 {
			t.tail = append(t.tail, data...)
			return
		}
		if data[1] == 'c' {
			t.Reset()
			data = data[2:]
			continue
		}
		if data[1] != '[' {
			data = data[2:]
			continue
		}
		final := -1
		for i := 2; i < len(data); i++ {
			if data[i] >= 0x40 && data[i] <= 0x7e {
				final = i
				break
			}
		}
		if final < 0 {
			if len(data) <= 64 {
				t.tail = append(t.tail, data...)
			}
			return
		}
		if (data[final] == 'h' || data[final] == 'l') && len(data) > 3 && data[2] == '?' {
			t.setPrivate(data[3:final], data[final] == 'h')
		}
		data = data[final+1:]
	}
}

func (t *terminalModeTracker) setPrivate(params []byte, enabled bool) {
	for _, value := range bytes.Split(params, []byte(";")) {
		switch string(value) {
		case "47", "1047", "1049":
			t.modes.AlternateScreen = enabled
		case "1000":
			t.modes.MouseClick = enabled
		case "1002":
			t.modes.MouseDrag = enabled
		case "1003":
			t.modes.MouseMotion = enabled
		case "1015":
			t.modes.MouseURXVT = enabled
		case "1006":
			t.modes.MouseSGR = enabled
		case "1004":
			t.modes.FocusEvents = enabled
		case "2004":
			t.modes.BracketedPaste = enabled
		}
	}
}

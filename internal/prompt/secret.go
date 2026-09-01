package prompt

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pinksaucepasta/paperboat/internal/selector"
)

// SecretOptions describes a hidden, raw single-line input. Unlike Text, Secret
// never trims the value and accepts an empty value after Enter.
type SecretOptions struct {
	Title       string
	Description string
	Placeholder string
	Initial     string
	Stdin       *os.File
	Output      io.Writer
	MaxBytes    int
}

type secretModel struct {
	options   SecretOptions
	input     textinput.Model
	value     []byte
	err       error
	confirmed bool
	canceled  bool
	width     int
}

// Secret reads one hidden value from an interactive terminal. The value is
// only returned to the caller and is never included in the prompt view or
// validation error.
func Secret(options SecretOptions) ([]byte, error) {
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stderr
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = 64 << 10
	}
	input := textinput.New()
	input.Placeholder = options.Placeholder
	input.EchoMode = textinput.EchoPassword
	input.EchoCharacter = '•'
	// Allow one extra rune so an over-limit input is rejected instead of being
	// silently truncated by bubbles/textinput.
	input.CharLimit = options.MaxBytes + 1
	input.SetValue(options.Initial)
	input.Focus()
	model := secretModel{options: options, input: input, width: 80}
	program := tea.NewProgram(model, selector.ProgramOptions(options.Stdin, options.Output)...)
	final, err := program.Run()
	if err != nil {
		return nil, fmt.Errorf("run hidden input: %w", err)
	}
	result := final.(secretModel)
	if result.canceled || !result.confirmed {
		clear(result.value)
		return nil, ErrCanceled
	}
	return result.value, nil
}

func (m secretModel) Init() tea.Cmd { return textinput.Blink }

func (m secretModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	var command tea.Cmd
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = max(32, message.Width)
		m.input.Width = max(20, m.width-8)
	case tea.KeyMsg:
		switch message.String() {
		case "ctrl+c", "esc":
			m.canceled = true
			return m, tea.Quit
		case "enter":
			value := []byte(m.input.Value())
			if len(value) > m.options.MaxBytes {
				clear(value)
				m.err = fmt.Errorf("value exceeds %d bytes", m.options.MaxBytes)
				return m, nil
			}
			m.input.SetValue("")
			m.value, m.confirmed = value, true
			return m, tea.Quit
		}
	}
	m.input, command = m.input.Update(message)
	return m, command
}

func (m secretModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render(m.options.Title)
	description := lipgloss.NewStyle().Faint(true).Render(m.options.Description)
	lines := []string{title, description, "", "  " + m.input.View()}
	if m.err != nil {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("  "+m.err.Error()))
	}
	lines = append(lines, "", lipgloss.NewStyle().Faint(true).Render("enter continue  esc cancel"))
	return strings.Join(lines, "\n")
}

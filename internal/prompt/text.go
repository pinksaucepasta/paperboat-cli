// Package prompt provides focused Bubble Tea inputs for interactive workflows.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pinksaucepasta/paperboat/internal/selector"
)

var ErrCanceled = errors.New("input canceled")

type TextOptions struct {
	Title       string
	Description string
	Placeholder string
	Initial     string
	Stdin       *os.File
	Output      io.Writer
	Validate    func(string) error
}

type textModel struct {
	options   TextOptions
	input     textinput.Model
	value     string
	err       error
	confirmed bool
	canceled  bool
	width     int
}

func Text(options TextOptions) (string, error) {
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stderr
	}
	input := textinput.New()
	input.Placeholder = options.Placeholder
	input.SetValue(options.Initial)
	input.Focus()
	model := textModel{options: options, input: input, width: 80}
	program := tea.NewProgram(model, selector.ProgramOptions(options.Stdin, options.Output)...)
	final, err := program.Run()
	if err != nil {
		return "", fmt.Errorf("run input: %w", err)
	}
	result := final.(textModel)
	if result.canceled || !result.confirmed {
		return "", ErrCanceled
	}
	return result.value, nil
}

func (m textModel) Init() tea.Cmd { return textinput.Blink }

func (m textModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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
			value := strings.TrimSpace(m.input.Value())
			if m.options.Validate != nil {
				if err := m.options.Validate(value); err != nil {
					m.err = err
					return m, nil
				}
			}
			m.value, m.confirmed = value, true
			return m, tea.Quit
		}
	}
	m.input, command = m.input.Update(message)
	return m, command
}

func (m textModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render(m.options.Title)
	description := lipgloss.NewStyle().Faint(true).Render(m.options.Description)
	lines := []string{title, description, "", "  " + m.input.View()}
	if m.err != nil {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("  "+m.err.Error()))
	}
	lines = append(lines, "", lipgloss.NewStyle().Faint(true).Render("enter continue  esc cancel"))
	return strings.Join(lines, "\n")
}

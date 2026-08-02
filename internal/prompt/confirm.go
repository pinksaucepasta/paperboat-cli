package prompt

import (
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pinksaucepasta/paperboat/internal/selector"
)

type ConfirmOptions struct {
	Title       string
	Description string
	Stdin       *os.File
	Output      io.Writer
}

type confirmModel struct {
	options ConfirmOptions
	yes     bool
	done    bool
}

func Confirm(options ConfirmOptions) (bool, error) {
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stderr
	}
	final, err := tea.NewProgram(confirmModel{options: options}, selector.ProgramOptions(options.Stdin, options.Output)...).Run()
	if err != nil {
		return false, fmt.Errorf("run confirmation: %w", err)
	}
	result := final.(confirmModel)
	return result.done && result.yes, nil
}

func (m confirmModel) Init() tea.Cmd { return nil }

func (m confirmModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch strings.ToLower(key.String()) {
		case "y", "enter":
			m.yes, m.done = true, true
			return m, tea.Quit
		case "n", "esc", "ctrl+c":
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m confirmModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3")).Render(m.options.Title)
	description := lipgloss.NewStyle().Faint(true).Render(m.options.Description)
	help := lipgloss.NewStyle().Faint(true).Render("enter/y confirm  n/esc cancel")
	return strings.Join([]string{title, description, "", "  Confirm", "", help}, "\n")
}

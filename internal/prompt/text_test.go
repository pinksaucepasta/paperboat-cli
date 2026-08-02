package prompt

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestTextModelValidatesBeforeQuitting(t *testing.T) {
	model := textModel{options: TextOptions{Validate: func(value string) error {
		if value == "" {
			return errors.New("required")
		}
		return nil
	}}, width: 80}
	model.input.SetValue("")
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(textModel)
	if command != nil || result.confirmed || result.err == nil {
		t.Fatalf("invalid input = confirmed %t error %v", result.confirmed, result.err)
	}
	result.input.SetValue("paperboat")
	updated, _ = result.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result = updated.(textModel)
	if !result.confirmed || result.value != "paperboat" {
		t.Fatalf("valid input = confirmed %t value %q", result.confirmed, result.value)
	}
}

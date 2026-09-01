package prompt

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func TestSecretModelPreservesRawWhitespaceAndAllowsEmpty(t *testing.T) {
	model := secretModel{options: SecretOptions{MaxBytes: 32_767}, width: 80}
	model.input.EchoMode = textinput.EchoPassword
	model.input.EchoCharacter = '•'
	model.input.SetValue("  canary value  ")
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(secretModel)
	if command == nil || !result.confirmed || string(result.value) != "  canary value  " {
		t.Fatalf("confirmed=%t value=%q command=%v", result.confirmed, result.value, command)
	}
	if strings.Contains(result.View(), "canary value") {
		t.Fatalf("hidden input view leaked value: %q", result.View())
	}

	model = secretModel{options: SecretOptions{MaxBytes: 32_767}, width: 80}
	model.input.EchoMode = textinput.EchoPassword
	model.input.EchoCharacter = '•'
	model.input.SetValue("")
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result = updated.(secretModel)
	if command == nil || !result.confirmed || len(result.value) != 0 {
		t.Fatalf("empty value was not accepted: confirmed=%t value=%q", result.confirmed, result.value)
	}
}

func TestSecretModelRejectsValueOverByteLimit(t *testing.T) {
	model := secretModel{options: SecretOptions{MaxBytes: 3}, width: 80}
	model.input.SetValue("1234")
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(secretModel)
	if command != nil || result.confirmed || result.err == nil || !strings.Contains(result.err.Error(), "3 bytes") {
		t.Fatalf("oversized value accepted: confirmed=%t err=%v command=%v", result.confirmed, result.err, command)
	}
}

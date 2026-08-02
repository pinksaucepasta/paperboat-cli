package prompt

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestConfirmModelAcceptsConfirmationKeys(t *testing.T) {
	for _, key := range []tea.KeyMsg{{Type: tea.KeyEnter}, {Type: tea.KeyRunes, Runes: []rune{'y'}}} {
		updated, command := (confirmModel{}).Update(key)
		result := updated.(confirmModel)
		if command == nil || !result.done || !result.yes {
			t.Fatalf("key %q = command %v, done %t, yes %t", key.String(), command, result.done, result.yes)
		}
	}
}

func TestConfirmModelAcceptsCancellationKeys(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'n'}},
		{Type: tea.KeyEsc},
		{Type: tea.KeyCtrlC},
	} {
		updated, command := (confirmModel{}).Update(key)
		result := updated.(confirmModel)
		if command == nil || !result.done || result.yes {
			t.Fatalf("key %q = command %v, done %t, yes %t", key.String(), command, result.done, result.yes)
		}
	}
}

package codexsession

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestValidateArgsRejectsPaperboatOwnedFlags(t *testing.T) {
	for _, args := range [][]string{{"--remote", "ws://x"}, {"--remote=x"}, {"--remote-auth-token-env=X"}, {"-C"}, {"--cd=/tmp"}} {
		if err := ValidateForwardedArgs(args); err == nil {
			t.Fatalf("validateArgs(%v) succeeded", args)
		}
	}
	if err := ValidateForwardedArgs([]string{"--model", "gpt-5"}); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryPickerNavigationAndSelection(t *testing.T) {
	picker := directoryPicker{rows: 4}
	picker.setPage("/workspace", []string{"api", "dashboard", "docs"})

	_, navigate, canceled := picker.input(pickerDown, 0)
	if navigate != "" || canceled || picker.selected != 1 {
		t.Fatalf("move down = selected %d navigate %q canceled %t", picker.selected, navigate, canceled)
	}
	selected, navigate, canceled := picker.input(pickerEnter, 0)
	if selected != "" || navigate != "/workspace/api" || canceled {
		t.Fatalf("open child = selected %q navigate %q canceled %t", selected, navigate, canceled)
	}

	picker.setPage("/workspace/api", []string{"cmd"})
	_, navigate, _ = picker.input(pickerBackspace, 0)
	if navigate != "/workspace/api/.." {
		t.Fatalf("parent navigation = %q", navigate)
	}
	picker.setPage("/workspace", []string{"api"})
	selected, _, _ = picker.input(pickerEnter, 0)
	if selected != "/workspace" {
		t.Fatalf("selected path = %q", selected)
	}
}

func TestDirectoryPickerFiltersAndBackspaceEdits(t *testing.T) {
	picker := directoryPicker{rows: 3}
	picker.setPage("~", []string{"api", "dashboard", "docs", ".config"})
	picker.input(0, 'd')
	if got := strings.Join(picker.visible, ","); got != "dashboard,docs" {
		t.Fatalf("filtered directories = %q", got)
	}
	_, navigate, _ := picker.input(pickerBackspace, 0)
	if navigate != "" || len(picker.visible) != 4 {
		t.Fatalf("backspace filter navigated to %q with %d rows", navigate, len(picker.visible))
	}
	_, navigate, _ = picker.input(pickerBackspace, 0)
	if navigate != "" {
		t.Fatalf("workspace root escaped to %q", navigate)
	}
}

func TestDirectoryPickerWrapsAndScrolls(t *testing.T) {
	picker := directoryPicker{rows: 2}
	picker.setPage("~", []string{"a", "b", "c"})
	picker.move(-1)
	if picker.selected != 3 || picker.offset != 2 {
		t.Fatalf("wrapped picker = selected %d offset %d", picker.selected, picker.offset)
	}
	picker.move(1)
	if picker.selected != 0 || picker.offset != 0 {
		t.Fatalf("second wrap = selected %d offset %d", picker.selected, picker.offset)
	}
}

func TestDirectoryPickerRenderHasStableWidth(t *testing.T) {
	picker := directoryPicker{rows: 3}
	picker.setPage("/workspace/a-path-that-is-much-too-long-for-this-terminal", []string{"a-directory-name-that-is-also-too-long", "docs"})
	var output bytes.Buffer
	renderDirectoryPicker(&output, picker, 40, 12)
	for _, line := range strings.Split(output.String(), "\r\n") {
		if width := ansi.StringWidth(line); width > 40 {
			t.Fatalf("rendered line width = %d: %q", width, line)
		}
	}
}
func TestCompatibleVersions(t *testing.T) {
	var warning bytes.Buffer
	if err := compatible("0.146.0", "0.146.1", &warning); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warning.String(), "patch version") {
		t.Fatalf("warning = %q", warning.String())
	}
	if err := compatible("0.146.0", "0.147.0", &warning); err == nil {
		t.Fatal("minor mismatch accepted")
	}
	if err := compatible("not-a-version", "0.146.0", &warning); err == nil {
		t.Fatal("malformed version accepted")
	}
}

package hostruntimecmd

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	for _, argument := range []string{"version", "--version", "-v"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{argument}, &stdout, &stderr); code != 0 {
			t.Fatalf("run %s exit code = %d, want 0; stderr = %q", argument, code, stderr.String())
		}
		if !strings.HasPrefix(stdout.String(), "pb ") {
			t.Fatalf("%s version output = %q", argument, stdout.String())
		}
	}
}

func TestBootstrapPromptsForDashboardCommandInputs(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Studio machine\n"))
	var output bytes.Buffer
	name := ""
	if err := promptBootstrapValue(reader, &output, "Machine name", &name); err != nil {
		t.Fatal(err)
	}
	if name != "Studio machine" {
		t.Fatalf("name=%q", name)
	}
	if output.String() != "Machine name: " {
		t.Fatalf("prompts=%q", output.String())
	}
}

func TestBootstrapFlagsDoNotConsumePromptInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("unused\n"))
	var output bytes.Buffer
	name := "Studio"
	if err := promptBootstrapValue(reader, &output, "Machine name", &name); err != nil {
		t.Fatal(err)
	}
	if name != "Studio" || output.Len() != 0 {
		t.Fatalf("name=%q prompts=%q", name, output.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run unknown exit code = %d, want 2", code)
	}
	if got := stderr.String(); got != "pb: unknown command \"serve\"\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestRemovedTransitionalCommandsAreUnknown(t *testing.T) {
	for _, arguments := range [][]string{{"enroll", "/tmp/config"}, {"send"}} {
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("arguments=%v code=%d stderr=%q", arguments, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "unknown command") {
			t.Fatalf("stderr=%q", stderr.String())
		}
	}
}

func TestHelpDoesNotExposeStandaloneRuntimeCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "bootstrap") || strings.Contains(stdout.String(), "preview create") || !strings.Contains(stdout.String(), "pb __runtime-host") {
		t.Fatalf("help=%q", stdout.String())
	}
}

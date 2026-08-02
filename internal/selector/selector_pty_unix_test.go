//go:build !windows

package selector

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func TestChooseRestoresTerminalAndSelects(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	type result struct {
		item Item
		err  error
	}
	done := make(chan result, 1)
	go func() {
		item, chooseErr := Choose(Options{Title: "Choose", Items: []Item{{ID: "one", Title: "One"}}, Stdin: slave, Output: &output})
		done <- result{item: item, err: chooseErr}
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte{'\r'}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.item.ID != "one" {
			t.Fatalf("choose = %+v, %v", got.item, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("selector did not handle input")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("selector did not restore terminal state")
	}
	if rendered := output.String(); !strings.Contains(rendered, "\x1b[?1049h") || !strings.Contains(rendered, "\x1b[?2004l") || !strings.Contains(rendered, "\x1b[?1049l") || !strings.HasSuffix(rendered, "\x1b[?25h") {
		t.Fatalf("terminal lifecycle output = %q", rendered)
	}
}

func TestChooseRequiredFilterUpdatesFromTerminalInput(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	type result struct {
		item Item
		err  error
	}
	done := make(chan result, 1)
	go func() {
		item, chooseErr := Choose(Options{
			Title:         "Send files",
			Items:         []Item{{ID: "report", Title: "report.pdf"}, {ID: "notes", Title: "notes.txt"}},
			RequireFilter: true,
			Stdin:         slave,
			Output:        &bytes.Buffer{},
		})
		done <- result{item: item, err: chooseErr}
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("notes\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.item.ID != "notes" {
			t.Fatalf("choose = %+v, %v", got.item, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("filtered selector did not handle terminal input")
	}
}

func TestChooseRecognizesBracketedPasteFromTerminal(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	type result struct {
		item Item
		err  error
	}
	done := make(chan result, 1)
	go func() {
		item, chooseErr := Choose(Options{
			Title: "Serve a file or directory", Items: []Item{{ID: "ordinary", Title: "ordinary"}}, Stdin: slave, Output: &bytes.Buffer{},
			InputSelection: func(value string) (Item, bool) {
				if value == "/tmp/My Report.pdf" {
					return Item{ID: "dropped", Title: "My Report.pdf"}, true
				}
				return Item{}, false
			},
		})
		done <- result{item: item, err: chooseErr}
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := master.Write([]byte("\x1b[200~/tmp/My Report.pdf\x1b[201~")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.item.ID != "dropped" {
			t.Fatalf("bracketed paste selection = %+v, %v", got.item, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("selector did not recognize bracketed paste")
	}
}

package selector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func TestPersistentScreenIsOwnedAcrossNestedControls(t *testing.T) {
	var output bytes.Buffer
	endOuter := BeginScreen(&output)
	endInner := BeginScreen(&output)
	if !ScreenActive() {
		t.Fatal("screen is not active")
	}
	endInner()
	if strings.Count(output.String(), enterAlternateScreen) != 1 || strings.Contains(output.String(), leaveAlternateScreen) {
		t.Fatalf("nested screen output=%q", output.String())
	}
	endOuter()
	if ScreenActive() || strings.Count(output.String(), leaveAlternateScreen) != 1 {
		t.Fatalf("closed screen output=%q", output.String())
	}
}

func TestLoadingReturnsWorkerError(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	want := errors.New("load failed")
	if got := Loading(context.Background(), "Machines", "Loading", reader, io.Discard, func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Fatalf("loading error=%v", got)
	}
}

func TestLoadingWaitsForCanceledWorker(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	started := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		<-started
		_, _ = writer.Write([]byte{3})
	}()
	err = Loading(context.Background(), "Machines", "Loading", reader, io.Discard, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("loading cancellation error=%v", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("loading returned before canceled worker finished")
	}
}

func TestLoadingViewUsesSimplePaperboatMark(t *testing.T) {
	model := loadingModel{title: "Machines", detail: "Loading", width: 80, height: 24}
	view := model.View()
	if strings.Contains(view, "~~~") || !strings.Contains(view, "▄█▄") || !strings.Contains(view, "Loading") {
		t.Fatalf("loading view=%q", view)
	}
}

func TestModelFiltersMetadataAndWraps(t *testing.T) {
	m := NewModel([]Item{
		{ID: "env_1", Title: "api", Description: "hosted project · ready"},
		{ID: "env_2", Title: "dadape", Description: "machine · online · linux/arm64"},
	}, 1)
	m.Type('a')
	m.Type('r')
	m.Type('m')
	if selected, ok := m.Selected(); !ok || selected.ID != "env_2" {
		t.Fatalf("metadata filter selected %+v, %t", selected, ok)
	}
	m.Backspace()
	m.Backspace()
	m.Backspace()
	m.Move(-1)
	if selected, _ := m.Selected(); selected.ID != "env_2" {
		t.Fatalf("wrapped selection = %+v", selected)
	}
}

func TestModelSupportsFuzzySubsequenceFiltering(t *testing.T) {
	m := NewModel([]Item{{ID: "one", Title: "screenshots/final-report.pdf"}, {ID: "two", Title: "notes.txt"}}, 3)
	for _, r := range "frpdf" {
		m.Type(r)
	}
	if selected, ok := m.Selected(); !ok || selected.ID != "one" {
		t.Fatalf("fuzzy selected=%+v ok=%t", selected, ok)
	}
}

func TestModelUsesFZFPathRanking(t *testing.T) {
	m := NewModel([]Item{
		{ID: "random", Title: "fixtures/source/domain/session.go"},
		{ID: "report", Title: "fixtures/archive/ZETA_release_notes.pdf"},
		{ID: "nested", Title: "fixtures/work/ZETA/notes.md"},
	}, 3)
	m.SetFilter("zeta")
	selected, ok := m.Selected()
	if !ok || (selected.ID != "report" && selected.ID != "nested") {
		t.Fatalf("path-ranked selection=%+v ok=%t", selected, ok)
	}
}

func TestModelPrioritizesExactBasenameOverFuzzyPath(t *testing.T) {
	m := NewModel([]Item{
		{ID: "fuzzy", Title: "fixtures/game/mod-loader.jar"},
		{ID: "exact", Title: "fixtures/source/go.mod"},
		{ID: "nested", Title: "fixtures/go/modules/readme.txt"},
	}, 3)
	m.SetFilter("go.mod")
	selected, ok := m.Selected()
	if !ok || selected.ID != "exact" {
		t.Fatalf("exact basename selection=%+v ok=%t", selected, ok)
	}
}

func TestModelCanHideItemsUntilFilteringStarts(t *testing.T) {
	m := NewModel([]Item{{ID: "one", Title: "report.pdf"}}, 3)
	m.requireFilter = true
	m.applyFilter()
	if _, ok := m.Selected(); ok || len(m.visible) != 0 {
		t.Fatal("unfiltered model exposed choices")
	}
	m.Type('r')
	if selected, ok := m.Selected(); !ok || selected.ID != "one" {
		t.Fatalf("filtered selection=%+v ok=%t", selected, ok)
	}
}

func TestChooserUpdatesRequiredFilterFromTypedRunes(t *testing.T) {
	choices := NewModel([]Item{{ID: "one", Title: "report.pdf"}, {ID: "two", Title: "notes.txt"}}, 3)
	choices.requireFilter = true
	choices.applyFilter()
	input := textinput.New()
	input.Focus()
	base := chooserModel{options: Options{RequireFilter: true}, choices: choices, input: input, width: 80, height: 24}
	updated, command := base.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("rpt")})
	result := updated.(chooserModel)
	if result.choices.Filter() != "rpt" {
		t.Fatalf("filter=%q command=%v", result.choices.Filter(), command)
	}
	if selected, ok := result.choices.Selected(); !ok || selected.ID != "one" {
		t.Fatalf("selected=%+v ok=%t", selected, ok)
	}
}

func TestModelNoMatchesCannotSelect(t *testing.T) {
	m := NewModel([]Item{{ID: "env_1", Title: "api"}}, 3)
	for _, r := range "missing" {
		m.Type(r)
	}
	if selected, ok := m.Selected(); ok {
		t.Fatalf("unexpected selection %+v", selected)
	}
}

func TestChooserDistinguishesBackFromQuit(t *testing.T) {
	base := chooserModel{options: Options{}, choices: NewModel(nil, 8), width: 80, height: 24}
	updated, command := base.Update(tea.KeyMsg{Type: tea.KeyEsc})
	back := updated.(chooserModel)
	if command == nil || !back.canceled || back.interrupted {
		t.Fatalf("escape = canceled %t interrupted %t command %v", back.canceled, back.interrupted, command)
	}
	updated, command = base.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	quit := updated.(chooserModel)
	if command == nil || quit.canceled || !quit.interrupted {
		t.Fatalf("ctrl+c = canceled %t interrupted %t command %v", quit.canceled, quit.interrupted, command)
	}
}

func TestChooserSupportsMouseWheelAndClick(t *testing.T) {
	base := chooserModel{options: Options{Header: "Paperboat", Title: "Machines"}, choices: NewModel([]Item{{ID: "one"}, {ID: "two"}}, 8), width: 80, height: 24}
	updated, _ := base.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
	scrolled := updated.(chooserModel)
	if selected, _ := scrolled.choices.Selected(); selected.ID != "two" {
		t.Fatalf("wheel selected %q", selected.ID)
	}
	updated, command := base.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, Y: 6})
	clicked := updated.(chooserModel)
	if command == nil || !clicked.confirmed || clicked.selected.ID != "two" {
		t.Fatalf("click confirmed=%t selected=%q command=%v", clicked.confirmed, clicked.selected.ID, command)
	}
}

func TestChooserMouseMotionUpdatesHoverSelection(t *testing.T) {
	base := chooserModel{options: Options{Title: "Machines"}, choices: NewModel([]Item{{ID: "one"}, {ID: "two"}}, 8), width: 80, height: 24}
	updated, command := base.Update(tea.MouseMsg{Action: tea.MouseActionMotion, X: 4, Y: 4})
	hovered := updated.(chooserModel)
	if command != nil {
		t.Fatalf("hover command=%v", command)
	}
	if selected, _ := hovered.choices.Selected(); selected.ID != "two" {
		t.Fatalf("hover selected %q", selected.ID)
	}
}

func TestChooserReturnsConfiguredKeyAction(t *testing.T) {
	base := chooserModel{options: Options{Title: "Machines", Actions: map[string]string{"ctrl+f": "favorite"}}, choices: NewModel([]Item{{ID: "one"}}, 8), width: 80, height: 24}
	updated, command := base.Update(tea.KeyMsg{Type: tea.KeyCtrlF})
	result := updated.(chooserModel)
	if command == nil || !result.confirmed || result.action != "favorite" || result.selected.ID != "one" {
		t.Fatalf("action=%q selected=%q confirmed=%t command=%v", result.action, result.selected.ID, result.confirmed, command)
	}
}

func TestChooserCanAcceptRecognizedPastedInput(t *testing.T) {
	input := textinput.New()
	input.Focus()
	base := chooserModel{
		options: Options{InputSelection: func(value string) (Item, bool) {
			return Item{ID: "drop", Title: value}, value == "/tmp/report.pdf"
		}},
		choices: NewModel([]Item{{ID: "ordinary"}}, 8), input: input, width: 80, height: 24,
	}
	updated, command := base.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/tmp/report.pdf")})
	result := updated.(chooserModel)
	if !result.confirmed || result.selected.ID != "drop" || command == nil {
		t.Fatalf("result=%#v command=%v", result, command)
	}
}

func TestChooserPreservesUnrecognizedPastedInputAsFilter(t *testing.T) {
	input := textinput.New()
	input.Focus()
	base := chooserModel{options: Options{InputSelection: func(string) (Item, bool) { return Item{}, false }}, choices: NewModel([]Item{{ID: "ordinary"}}, 8), input: input, width: 80, height: 24}
	updated, _ := base.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ordinary text")})
	result := updated.(chooserModel)
	if result.confirmed || result.input.Value() != "ordinary text" || result.choices.Filter() != "ordinary text" {
		t.Fatalf("input=%q filter=%q confirmed=%v", result.input.Value(), result.choices.Filter(), result.confirmed)
	}
}

func TestChooserReturnsHeaderClickAction(t *testing.T) {
	base := chooserModel{options: Options{Header: "Paperboat\nVersion\nmasked", HeaderActions: map[int]string{2: "reveal"}}, choices: NewModel([]Item{{ID: "one"}}, 8), width: 80, height: 24}
	updated, command := base.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 20, Y: 2})
	result := updated.(chooserModel)
	if command == nil || !result.confirmed || result.action != "reveal" {
		t.Fatalf("action=%q confirmed=%t command=%v", result.action, result.confirmed, command)
	}
}

func TestEmptyChooserRendersUsefulState(t *testing.T) {
	model := chooserModel{options: Options{Title: "Public previews", Empty: "No public previews yet"}, choices: NewModel(nil, 8), width: 80, height: 24}
	view := model.View()
	if !strings.Contains(view, "No public previews yet") || strings.Contains(view, "No matches") {
		t.Fatalf("empty view = %q", view)
	}
	if _, ok := model.choices.Selected(); ok {
		t.Fatal("empty chooser unexpectedly selected an item")
	}
}

func TestChooserRendersActionItemsDistinctly(t *testing.T) {
	model := chooserModel{
		options: Options{Title: "Machines"},
		choices: NewModel([]Item{{ID: "machine", Title: "Remote"}, {ID: "add", Title: "+ Add machine", Action: true}}, 8),
		width:   80,
		height:  24,
	}
	view := model.View()
	if !strings.Contains(view, actionStyle.Render("     + Add machine")) {
		t.Fatalf("action item was not accented: %q", view)
	}
}

func TestChooserRendersFavoriteItemsWithAccent(t *testing.T) {
	model := chooserModel{
		options: Options{Title: "Machines"},
		choices: NewModel([]Item{{ID: "plain", Title: "Plain"}, {ID: "favorite", Title: "Favorite", Favorite: true}}, 8),
		width:   80,
		height:  24,
	}
	view := model.View()
	if !strings.Contains(view, favoriteStyle.Render("     Favorite")+" "+favoriteMarker.Render("◆")) {
		t.Fatalf("favorite item was not accented: %q", view)
	}
}

func TestSelectorErrorsRemainDistinct(t *testing.T) {
	if errors.Is(ErrCanceled, ErrInterrupted) || errors.Is(ErrInterrupted, ErrCanceled) {
		t.Fatal("back and interrupt errors must remain distinct")
	}
}

func BenchmarkModelFiltersFiftyThousandPaths(b *testing.B) {
	items := make([]Item, 50000)
	for index := range items {
		items[index] = Item{ID: fmt.Sprintf("file-%d", index), Title: fmt.Sprintf("fixtures/project-%05d/source/component.go", index)}
	}
	items[31415] = Item{ID: "zeta", Title: "fixtures/archive/ZETA_release_notes.pdf"}
	model := NewModel(items, 8)
	b.ResetTimer()
	for range b.N {
		model.SetFilter("zeta")
	}
}

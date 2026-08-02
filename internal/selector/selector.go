// Package selector provides Paperboat's shared interactive list selection UI.
package selector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/junegunn/fzf/src/algo"
	"github.com/junegunn/fzf/src/util"
)

func init() {
	algo.Init("path")
}

var ErrCanceled = errors.New("selection canceled")
var ErrInterrupted = errors.New("selection interrupted")

var persistentScreen atomic.Int32

const enterAlternateScreen = "\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l"
const leaveAlternateScreen = "\x1b[?25h\x1b[?1049l"

// BeginScreen keeps a hierarchy of selectors, prompts, and loading states on
// one alternate screen. The returned function must be called exactly once.
func BeginScreen(output io.Writer) func() {
	if output == nil {
		output = os.Stderr
	}
	if persistentScreen.Add(1) == 1 {
		_, _ = io.WriteString(output, enterAlternateScreen)
	}
	return func() {
		if persistentScreen.Add(-1) == 0 {
			_, _ = io.WriteString(output, leaveAlternateScreen)
		}
	}
}

// ProgramOptions makes other Bubble Tea controls participate in the active
// Paperboat screen instead of briefly restoring the normal terminal.
func ProgramOptions(input *os.File, output io.Writer) []tea.ProgramOption {
	options := []tea.ProgramOption{tea.WithInput(input), tea.WithOutput(output), tea.WithMouseAllMotion()}
	if persistentScreen.Load() == 0 {
		return append(options, tea.WithAltScreen())
	}
	_, _ = io.WriteString(output, "\x1b[2J\x1b[H")
	return options
}

func ScreenActive() bool { return persistentScreen.Load() > 0 }

type Item struct {
	ID          string
	Title       string
	Description string
	Search      string
	Action      bool
	Favorite    bool
}

type Options struct {
	Header         string
	Title          string
	Subtitle       string
	Items          []Item
	Empty          string
	Stdin          *os.File
	Output         io.Writer
	Initial        string
	Footer         string
	Actions        map[string]string
	RequireFilter  bool
	HeaderActions  map[int]string
	InputSelection func(string) (Item, bool)
}

type Result struct {
	Item   Item
	Action string
}

type rankedMatch struct {
	index, class, score, start, length int
}

type Model struct {
	items         []Item
	primary       []string
	searchable    []string
	searchChars   []util.Chars
	matches       []rankedMatch
	workerMatches [][]rankedMatch
	workerSlabs   []*util.Slab
	visible       []int
	filter        []rune
	selected      int
	offset        int
	rows          int
	requireFilter bool
}

func NewModel(items []Item, rows int) *Model {
	searchable := make([]string, len(items))
	primary := make([]string, len(items))
	searchChars := make([]util.Chars, len(items))
	for index, item := range items {
		primary[index] = strings.ToLower(item.Title)
		searchable[index] = strings.ToLower(strings.TrimSpace(strings.Join([]string{item.Title, item.Search, item.Description}, " ")))
		searchChars[index] = util.ToChars([]byte(searchable[index]))
	}
	workerCount := min(max(1, runtime.GOMAXPROCS(0)), 8, max(1, len(items)))
	workerMatches := make([][]rankedMatch, workerCount)
	workerSlabs := make([]*util.Slab, workerCount)
	for index := range workerCount {
		workerMatches[index] = make([]rankedMatch, 0, (len(items)+workerCount-1)/workerCount)
		workerSlabs[index] = util.MakeSlab(100*1024, 2048)
	}
	m := &Model{
		items: items, primary: primary, searchable: searchable, searchChars: searchChars,
		matches: make([]rankedMatch, 0, len(items)), workerMatches: workerMatches, workerSlabs: workerSlabs,
		rows: max(1, rows),
	}
	m.applyFilter()
	return m
}

func (m *Model) applyFilter() {
	query := strings.ToLower(string(m.filter))
	m.visible = m.visible[:0]
	if m.requireFilter && query == "" {
		m.selected, m.offset = 0, 0
		return
	}
	if query == "" {
		for index := range m.items {
			m.visible = append(m.visible, index)
		}
	} else {
		pattern := []rune(query)
		m.matches = m.matches[:0]
		var workers sync.WaitGroup
		for workerIndex := range m.workerMatches {
			workers.Add(1)
			go func(workerIndex int) {
				defer workers.Done()
				matches := m.workerMatches[workerIndex][:0]
				for index := workerIndex; index < len(m.searchChars); index += len(m.workerMatches) {
					result, _ := algo.FuzzyMatchV2(false, false, true, &m.searchChars[index], pattern, false, m.workerSlabs[workerIndex])
					if result.Start >= 0 {
						matches = append(matches, rankedMatch{index: index, class: matchClass(m.primary[index], query), score: result.Score, start: result.Start, length: len(m.searchable[index])})
					}
				}
				m.workerMatches[workerIndex] = matches
			}(workerIndex)
		}
		workers.Wait()
		for _, matches := range m.workerMatches {
			m.matches = append(m.matches, matches...)
		}
		slices.SortFunc(m.matches, func(a, b rankedMatch) int {
			if a.class != b.class {
				return a.class - b.class
			}
			if a.score != b.score {
				return b.score - a.score
			}
			if a.length != b.length {
				return a.length - b.length
			}
			if a.start != b.start {
				return a.start - b.start
			}
			return a.index - b.index
		})
		for _, match := range m.matches {
			m.visible = append(m.visible, match.index)
		}
	}
	if m.selected >= len(m.visible) {
		m.selected = max(0, len(m.visible)-1)
	}
	m.ensureVisible()
}

func matchClass(primary, query string) int {
	normalized := strings.ReplaceAll(primary, "\\", "/")
	base := normalized
	if separator := strings.LastIndexByte(normalized, '/'); separator >= 0 {
		base = normalized[separator+1:]
	}
	if strings.HasPrefix(base, query) {
		return 0
	}
	if strings.Contains(base, query) {
		return 1
	}
	if strings.Contains(normalized, query) {
		return 2
	}
	return 3
}

func (m *Model) ensureVisible() {
	if m.selected < m.offset {
		m.offset = m.selected
	}
	if m.selected >= m.offset+m.rows {
		m.offset = m.selected - m.rows + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *Model) Move(delta int) {
	if len(m.visible) == 0 {
		return
	}
	m.selected = (m.selected + delta + len(m.visible)) % len(m.visible)
	m.ensureVisible()
}

func (m *Model) Type(r rune) {
	if r == 0 || unicode.IsControl(r) {
		return
	}
	m.filter = append(m.filter, r)
	m.selected, m.offset = 0, 0
	m.applyFilter()
}

func (m *Model) Backspace() {
	if len(m.filter) == 0 {
		return
	}
	m.filter = m.filter[:len(m.filter)-1]
	m.selected, m.offset = 0, 0
	m.applyFilter()
}

func (m *Model) SetFilter(value string) {
	m.filter = []rune(value)
	m.selected, m.offset = 0, 0
	m.applyFilter()
}

func (m *Model) Selected() (Item, bool) {
	if len(m.visible) == 0 {
		return Item{}, false
	}
	return m.items[m.visible[m.selected]], true
}

func (m *Model) Filter() string { return string(m.filter) }

func Choose(options Options) (selected Item, err error) {
	result, err := ChooseWithAction(options)
	return result.Item, err
}

func ChooseWithAction(options Options) (selection Result, err error) {
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stderr
	}
	if options.Empty == "" {
		options.Empty = "No choices are available."
	}
	input := textinput.New()
	input.Prompt = ""
	input.Placeholder = "type to filter"
	input.SetValue(options.Initial)
	input.Focus()
	model := chooserModel{options: options, choices: NewModel(options.Items, 8), input: input, width: 80, height: 24}
	model.choices.requireFilter = options.RequireFilter
	model.choices.SetFilter(options.Initial)
	program := tea.NewProgram(model, ProgramOptions(options.Stdin, options.Output)...)
	final, runErr := program.Run()
	if runErr != nil {
		return Result{}, fmt.Errorf("run selector: %w", runErr)
	}
	result := final.(chooserModel)
	if result.interrupted {
		return Result{}, ErrInterrupted
	}
	if result.canceled || !result.confirmed {
		return Result{}, ErrCanceled
	}
	return Result{Item: result.selected, Action: result.action}, nil
}

type loadDoneMsg struct{ err error }
type loadTickMsg struct{}

type loadingModel struct {
	title, detail string
	work          func(context.Context) error
	cancel        context.CancelFunc
	done          bool
	interrupted   bool
	err           error
	frame         int
	width, height int
}

func (m loadingModel) Init() tea.Cmd {
	return tea.Batch(func() tea.Msg { return loadDoneMsg{err: m.work(context.Background())} }, loadingTick())
}

func loadingTick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return loadTickMsg{} })
}

func (m loadingModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(32, message.Width), max(10, message.Height)
	case tea.KeyMsg:
		if (message.String() == "ctrl+c" || message.String() == "esc") && !m.interrupted {
			m.interrupted = true
			m.cancel()
			m.detail = "Canceling"
			return m, nil
		}
	case loadDoneMsg:
		m.done, m.err = true, message.err
		return m, tea.Quit
	case loadTickMsg:
		m.frame = (m.frame + 1) % 4
		return m, loadingTick()
	}
	return m, nil
}

func (m loadingModel) View() string {
	lineWidth := max(20, m.width-4)
	boat := []string{"      ▄█▄", "  ▄▄▝▀▀▀▀▀▘▄▄", "   ▀███████▀"}
	lines := []string{titleStyle.Render(ansi.Truncate(m.title, lineWidth, "...")), ""}
	for _, line := range boat {
		lines = append(lines, ansi.Truncate(line, lineWidth, "..."))
	}
	lines = append(lines, "", fmt.Sprintf("  %c  %s", "|/-\\"[m.frame], ansi.Truncate(m.detail, max(1, lineWidth-5), "...")))
	for len(lines) < m.height-1 {
		lines = append(lines, "")
	}
	lines = append(lines, helpStyle.Render("esc cancel"))
	return strings.Join(lines, "\n")
}

// Loading runs work while an animated state remains visible in the current TUI.
func Loading(ctx context.Context, title, detail string, input *os.File, output io.Writer, work func(context.Context) error) error {
	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stderr
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	model := loadingModel{title: title, detail: detail, width: 80, height: 24, cancel: cancel, work: func(context.Context) error { return work(workCtx) }}
	programOptions := ProgramOptions(input, output)
	if ScreenActive() {
		_, _ = io.WriteString(output, model.View()+"\x1b[H")
	}
	final, err := tea.NewProgram(model, programOptions...).Run()
	if err != nil {
		return fmt.Errorf("run loading state: %w", err)
	}
	result := final.(loadingModel)
	if result.interrupted {
		return ErrCanceled
	}
	return result.err
}

type chooserModel struct {
	options     Options
	choices     *Model
	input       textinput.Model
	width       int
	height      int
	selected    Item
	confirmed   bool
	action      string
	canceled    bool
	interrupted bool
}

func (m chooserModel) Init() tea.Cmd { return textinput.Blink }

func (m chooserModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(32, message.Width), max(10, message.Height)
		m.input.Width = max(8, m.width-24)
		m.choices.rows = max(2, (m.height-7-headerLineCount(m.options.Header))/2)
		m.choices.ensureVisible()
	case tea.KeyMsg:
		if action, ok := m.options.Actions[message.String()]; ok {
			m.action = action
			m.selected, _ = m.choices.Selected()
			m.confirmed = true
			return m, tea.Quit
		}
		switch message.String() {
		case "ctrl+c":
			m.interrupted = true
			return m, tea.Quit
		case "esc":
			m.canceled = true
			return m, tea.Quit
		case "enter":
			if item, ok := m.choices.Selected(); ok {
				m.selected, m.confirmed = item, true
				return m, tea.Quit
			}
		case "up", "ctrl+k":
			m.choices.Move(-1)
			return m, nil
		case "down", "ctrl+n":
			m.choices.Move(1)
			return m, nil
		}
		var command tea.Cmd
		m.input, command = m.input.Update(message)
		m.choices.SetFilter(m.input.Value())
		if m.options.InputSelection != nil {
			if selected, ok := m.options.InputSelection(m.input.Value()); ok {
				m.selected, m.confirmed = selected, true
				return m, tea.Quit
			}
		}
		return m, command
	case tea.MouseMsg:
		if message.Action == tea.MouseActionPress && message.Button == tea.MouseButtonLeft {
			if action, ok := m.options.HeaderActions[message.Y]; ok {
				m.action, m.confirmed = action, true
				return m, tea.Quit
			}
		}
		if message.Action == tea.MouseActionMotion {
			if index, ok := m.itemAtRow(message.Y); ok {
				m.choices.selected = index
				m.choices.ensureVisible()
			}
			break
		}
		switch message.Button {
		case tea.MouseButtonWheelUp:
			m.choices.Move(-1)
		case tea.MouseButtonWheelDown:
			m.choices.Move(1)
		case tea.MouseButtonLeft:
			if message.Action != tea.MouseActionPress {
				break
			}
			index, ok := m.itemAtRow(message.Y)
			if !ok {
				break
			}
			m.choices.selected = index
			if item, selected := m.choices.Selected(); selected {
				m.selected, m.confirmed = item, true
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m chooserModel) itemAtRow(row int) (int, bool) {
	first := headerLineCount(m.options.Header) + 2
	if m.options.Subtitle != "" {
		first++
	}
	if row < first {
		return 0, false
	}
	index := m.choices.offset + (row-first)/2
	end := min(len(m.choices.visible), m.choices.offset+m.choices.rows)
	return index, index >= m.choices.offset && index < end
}

var (
	brandColor     = lipgloss.AdaptiveColor{Light: "#1447E6", Dark: "#6F8CFF"}
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(brandColor)
	subtitleStyle  = lipgloss.NewStyle().Faint(true)
	selectedStyle  = lipgloss.NewStyle().Reverse(true)
	actionStyle    = lipgloss.NewStyle().Bold(true).Foreground(brandColor)
	favoriteStyle  = lipgloss.NewStyle().Bold(true).Foreground(brandColor)
	favoriteMarker = lipgloss.NewStyle().Bold(true).Foreground(brandColor)
	helpStyle      = lipgloss.NewStyle().Faint(true)
	filterStyle    = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("15")).Padding(0, 1)
)

func (m chooserModel) View() string {
	lineWidth := max(20, m.width-4)
	lines := make([]string, 0, m.height)
	if m.options.Header != "" {
		for _, line := range strings.Split(m.options.Header, "\n") {
			lines = append(lines, ansi.Truncate(line, lineWidth, "..."))
		}
		lines = append(lines, "")
	}
	lines = append(lines, titleStyle.Render(ansi.Truncate(m.options.Title, lineWidth, "...")))
	if m.options.Subtitle != "" {
		lines = append(lines, subtitleStyle.Render(ansi.Truncate(m.options.Subtitle, lineWidth, "...")))
	}
	lines = append(lines, "")
	end := min(len(m.choices.visible), m.choices.offset+m.choices.rows)
	for visibleIndex := m.choices.offset; visibleIndex < end; visibleIndex++ {
		item := m.choices.items[m.choices.visible[visibleIndex]]
		prefix := "     "
		if visibleIndex == m.choices.selected {
			prefix = "  >  "
		}
		plainTitle := prefix + item.Title
		if item.Favorite {
			plainTitle += " ◆"
		}
		title := ansi.Truncate(plainTitle, lineWidth, "...")
		detail := ansi.Truncate("     "+item.Description, lineWidth, "...")
		if visibleIndex == m.choices.selected {
			title = selectedStyle.Render(title + strings.Repeat(" ", max(0, lineWidth-ansi.StringWidth(title))))
		} else if item.Action {
			title = actionStyle.Render(title)
		} else if item.Favorite {
			name := ansi.Truncate(prefix+item.Title, max(1, lineWidth-2), "...")
			title = favoriteStyle.Render(name) + " " + favoriteMarker.Render("◆")
		}
		lines = append(lines, title, subtitleStyle.Render(detail))
	}
	if len(m.choices.visible) == 0 {
		if m.choices.requireFilter && m.choices.Filter() == "" {
			lines = append(lines, subtitleStyle.Render("  Start typing a filename or path to search."), "")
		} else {
			empty := "No matches"
			if len(m.choices.items) == 0 {
				empty = m.options.Empty
			}
			lines = append(lines, subtitleStyle.Render("  "+ansi.Truncate(empty, max(1, lineWidth-2), "...")), "")
		}
	}
	for len(lines) < m.height-2 {
		lines = append(lines, "")
	}
	footer := m.options.Footer
	if footer == "" {
		footer = "↑/↓ move  enter/click select  backspace filter  esc back"
	}
	filterLabel := "Filter"
	if m.choices.requireFilter {
		filterLabel = "Search files"
	}
	filterLine := filterLabel + "  " + m.input.View()
	filterLine += strings.Repeat(" ", max(0, lineWidth-2-ansi.StringWidth(filterLine)))
	lines = append(lines,
		filterStyle.Render(ansi.Truncate(filterLine, max(1, lineWidth-2), "...")),
		helpStyle.Render(ansi.Truncate(footer, lineWidth, "...")),
	)
	return strings.Join(lines, "\n")
}

func headerLineCount(header string) int {
	if header == "" {
		return 0
	}
	return strings.Count(header, "\n") + 2
}

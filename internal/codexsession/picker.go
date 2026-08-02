package codexsession

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"golang.org/x/term"
)

const (
	pickerEnter = iota + 1
	pickerUp
	pickerDown
	pickerBackspace
	pickerCancel
)

type directoryPicker struct {
	path     string
	all      []string
	visible  []string
	filter   []rune
	selected int
	offset   int
	rows     int
}

func (p *directoryPicker) setPage(path string, directories []string) {
	p.path, p.all, p.filter, p.selected, p.offset = path, directories, nil, 0, 0
	p.applyFilter()
}

func (p *directoryPicker) applyFilter() {
	query := strings.ToLower(string(p.filter))
	p.visible = p.visible[:0]
	for _, name := range p.all {
		if query == "" || strings.Contains(strings.ToLower(name), query) {
			p.visible = append(p.visible, name)
		}
	}
	if p.selected > len(p.visible) {
		p.selected = len(p.visible)
	}
	p.ensureVisible()
}

func (p *directoryPicker) ensureVisible() {
	if p.selected < p.offset {
		p.offset = p.selected
	}
	if p.selected >= p.offset+p.rows {
		p.offset = p.selected - p.rows + 1
	}
	if p.offset < 0 {
		p.offset = 0
	}
}

func (p *directoryPicker) move(delta int) {
	p.selected += delta
	if p.selected < 0 {
		p.selected = len(p.visible)
	}
	if p.selected > len(p.visible) {
		p.selected = 0
	}
	p.ensureVisible()
}

func (p *directoryPicker) input(key int, typed rune) (selectPath, navigatePath string, canceled bool) {
	switch key {
	case pickerCancel:
		return "", "", true
	case pickerUp:
		p.move(-1)
	case pickerDown:
		p.move(1)
	case pickerBackspace:
		if len(p.filter) > 0 {
			p.filter = p.filter[:len(p.filter)-1]
			p.selected = 0
			p.applyFilter()
			return "", "", false
		}
		if p.path != "~" {
			return "", p.path + "/..", false
		}
	case pickerEnter:
		if p.selected == 0 {
			return p.path, "", false
		}
		return "", remoteJoin(p.path, p.visible[p.selected-1]), false
	default:
		if typed != 0 && !unicode.IsControl(typed) {
			p.filter = append(p.filter, typed)
			p.selected = 0
			p.applyFilter()
		}
	}
	return "", "", false
}

func remoteJoin(parent, child string) string {
	return strings.TrimSuffix(parent, "/") + "/" + child
}

func loadDirectories(ctx context.Context, o Options, d api.CodexDescriptor, path string) (directoryPage, error) {
	var result directoryPage
	cursor := ""
	for {
		page, err := directories(ctx, o, d, path, cursor)
		if err != nil {
			return directoryPage{}, err
		}
		if result.Path == "" {
			result.Path = page.Path
		}
		result.Directories = append(result.Directories, page.Directories...)
		if page.NextCursor == "" {
			return result, nil
		}
		cursor = page.NextCursor
	}
}

func pickDirectory(ctx context.Context, o Options, d api.CodexDescriptor) (selected string, err error) {
	fd := int(o.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("open remote directory selector: %w", err)
	}
	fmt.Fprint(o.Stderr, "\x1b[?1049h\x1b[?25l")
	defer func() {
		fmt.Fprint(o.Stderr, "\x1b[0m\x1b[?25h\x1b[?1049l")
		if restoreErr := term.Restore(fd, oldState); err == nil && restoreErr != nil {
			err = fmt.Errorf("restore terminal after directory selector: %w", restoreErr)
		}
	}()

	width, height, sizeErr := term.GetSize(fd)
	if sizeErr != nil || width < 32 {
		width = 80
	}
	if sizeErr != nil || height < 10 {
		height = 24
	}
	picker := directoryPicker{rows: max(3, height-8)}
	page, err := loadDirectories(ctx, o, d, "~")
	if err != nil {
		return "", err
	}
	picker.setPage(page.Path, page.Directories)
	reader := bufio.NewReader(o.Stdin)
	for {
		renderDirectoryPicker(o.Stderr, picker, width, height)
		key, typed, readErr := readPickerKey(reader)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return "", ErrCanceled
			}
			return "", readErr
		}
		selected, navigate, canceled := picker.input(key, typed)
		if canceled {
			return "", ErrCanceled
		}
		if selected != "" {
			return selected, nil
		}
		if navigate != "" {
			page, err = loadDirectories(ctx, o, d, navigate)
			if err != nil {
				return "", err
			}
			picker.setPage(page.Path, page.Directories)
		}
	}
}

func readPickerKey(reader *bufio.Reader) (int, rune, error) {
	r, _, err := reader.ReadRune()
	if err != nil {
		return 0, 0, err
	}
	switch r {
	case '\r', '\n':
		return pickerEnter, 0, nil
	case 3, 27:
		if r == 27 && reader.Buffered() >= 2 {
			next, _ := reader.ReadByte()
			direction, _ := reader.ReadByte()
			if next == '[' && direction == 'A' {
				return pickerUp, 0, nil
			}
			if next == '[' && direction == 'B' {
				return pickerDown, 0, nil
			}
		}
		return pickerCancel, 0, nil
	case 8, 127:
		return pickerBackspace, 0, nil
	case 11:
		return pickerUp, 0, nil
	case 14:
		return pickerDown, 0, nil
	}
	return 0, r, nil
}

func renderDirectoryPicker(w io.Writer, p directoryPicker, width, height int) {
	lineWidth := max(20, width-4)
	rowCount := min(p.rows, height-8)
	lines := []string{
		"\x1b[1;36mChoose a remote folder\x1b[0m",
		"\x1b[2m" + ansi.Truncate(p.path, lineWidth, "...") + "\x1b[0m",
		"",
	}
	items := append([]string{"Use this folder"}, p.visible...)
	end := min(len(items), p.offset+rowCount)
	for i := p.offset; i < end; i++ {
		icon := "  >  "
		label := items[i]
		if i > 0 {
			icon, label = "     ", label+"/"
		}
		row := ansi.Truncate(icon+label, lineWidth, "...")
		if i == p.selected {
			row = "\x1b[7m" + row + strings.Repeat(" ", max(0, lineWidth-ansi.StringWidth(row))) + "\x1b[0m"
		}
		lines = append(lines, row)
	}
	for len(lines) < height-3 {
		lines = append(lines, "")
	}
	filter := string(p.filter)
	if filter == "" {
		filter = "type to filter"
	}
	lines = append(lines,
		"\x1b[2m"+ansi.Truncate("Filter: "+filter, lineWidth, "...")+"\x1b[0m",
		"\x1b[2m"+ansi.Truncate("↑/↓ move  enter open/select  backspace parent  esc cancel", lineWidth, "...")+"\x1b[0m",
	)
	fmt.Fprint(w, "\x1b[H\x1b[2J"+strings.Join(lines, "\r\n"))
}

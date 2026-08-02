package serve

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	shlex "github.com/anmitsu/go-shlex"
)

const (
	bracketedPasteStart = "\x1b[200~"
	bracketedPasteEnd   = "\x1b[201~"
)

// ParseDroppedFile returns consumed=false unless input consists exclusively of one
// valid local regular-file path. Callers can then preserve ordinary pasted text.
func ParseDroppedFile(input string) (source Source, consumed bool) {
	value := input
	if strings.HasPrefix(value, bracketedPasteStart) && strings.HasSuffix(value, bracketedPasteEnd) {
		value = strings.TrimSuffix(strings.TrimPrefix(value, bracketedPasteStart), bracketedPasteEnd)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return Source{}, false
	}
	tokens, err := shlex.Split(value, true)
	if err != nil || len(tokens) != 1 {
		return Source{}, false
	}
	candidate := tokens[0]
	if strings.HasPrefix(candidate, "file://") {
		parsed, parseErr := url.Parse(candidate)
		if parseErr != nil || parsed.Scheme != "file" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "" && parsed.Host != "localhost" {
			return Source{}, false
		}
		candidate = parsed.Path
		if runtime.GOOS == "windows" && len(candidate) >= 3 && candidate[0] == '/' && candidate[2] == ':' {
			candidate = candidate[1:]
		}
	}
	if !filepath.IsAbs(candidate) {
		return Source{}, false
	}
	resolved, err := ResolveSource(candidate)
	if err != nil || resolved.Kind != SourceFile {
		return Source{}, false
	}
	return resolved, true
}

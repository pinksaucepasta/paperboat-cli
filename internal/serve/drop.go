package serve

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
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
	candidate, ok := droppedFileCandidate(value)
	if !ok {
		return Source{}, false
	}
	if strings.HasPrefix(candidate, "file://") {
		if runtime.GOOS == "windows" && len(candidate) >= 12 && isASCIILetter(candidate[7]) && candidate[8] == ':' && strings.EqualFold(candidate[9:12], "%5c") {
			decoded, decodeErr := url.PathUnescape(candidate[7:])
			if decodeErr != nil {
				return Source{}, false
			}
			candidate = decoded
		} else {
			parsed, parseErr := url.Parse(candidate)
			if parseErr != nil || parsed.Scheme != "file" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "" && parsed.Host != "localhost" {
				return Source{}, false
			}
			candidate = parsed.Path
			if runtime.GOOS == "windows" && len(candidate) >= 3 && candidate[0] == '/' && candidate[2] == ':' {
				candidate = candidate[1:]
			}
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

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

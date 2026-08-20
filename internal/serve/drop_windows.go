//go:build windows

package serve

import "strings"

// Windows paths use backslash as a separator, so a POSIX shell lexer corrupts
// them. Accept one literal, one wholly quoted value, or the common escaped-space
// form emitted by terminal drag and drop. ResolveSource remains the authority
// that requires the resulting path to be a real regular file.
func droppedFileCandidate(value string) (string, bool) {
	if strings.ContainsAny(value, "\r\n\t") {
		return "", false
	}
	if strings.HasPrefix(value, "file://") {
		return value, true
	}
	if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
		candidate := value[1 : len(value)-1]
		if candidate == "" || strings.ContainsAny(candidate, "\"'") {
			return "", false
		}
		return candidate, true
	}
	return strings.ReplaceAll(value, `\ `, " "), true
}

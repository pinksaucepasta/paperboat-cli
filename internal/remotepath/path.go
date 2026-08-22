// Package remotepath validates paths that belong to a remote machine without
// applying the local machine's operating-system path semantics.
package remotepath

import "strings"

// Absolute reports whether value is an absolute Unix or Windows path.
func Absolute(value string) bool {
	return UnixAbsolute(value) || WindowsAbsolute(value)
}

// AbsoluteForTarget reports whether value is absolute for the target platform.
// When platform is unavailable, reference is used to infer the target's path
// convention. A missing or invalid reference leaves either convention valid.
func AbsoluteForTarget(platform, reference, value string) bool {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "windows":
		return WindowsAbsolute(value)
	case "darwin", "linux":
		return UnixAbsolute(value)
	}
	if WindowsAbsolute(reference) {
		return WindowsAbsolute(value)
	}
	if UnixAbsolute(reference) {
		return UnixAbsolute(value)
	}
	return Absolute(value)
}

// UnixAbsolute reports whether value is an absolute Unix path.
func UnixAbsolute(value string) bool {
	return valid(value) && strings.HasPrefix(value, "/")
}

// WindowsAbsolute reports whether value is a drive-qualified or UNC path.
func WindowsAbsolute(value string) bool {
	if !valid(value) {
		return false
	}
	value = strings.ReplaceAll(value, "/", `\`)
	if len(value) >= 3 && asciiLetter(value[0]) && value[1] == ':' && value[2] == '\\' {
		return true
	}
	if strings.HasPrefix(value, `\\`) {
		parts := strings.Split(value[2:], `\`)
		return len(parts) >= 2 && parts[0] != "" && parts[1] != ""
	}
	return false
}

func valid(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func asciiLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

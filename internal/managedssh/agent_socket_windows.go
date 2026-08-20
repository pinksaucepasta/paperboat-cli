//go:build windows

package managedssh

import (
	"crypto/sha256"
	"encoding/hex"
)

// ownerAgentSocket deliberately uses the native OpenSSH agent endpoint form.
// A user SID-derived opaque name avoids a shared, spoofable global pipe while
// remaining stable across Paperboat process restarts.
func ownerAgentSocket(_ string) (string, error) {
	sid, err := currentManagedSSHSID()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(sid))
	return `\\.\pipe\paperboat-ssh-agent-` + hex.EncodeToString(sum[:16]), nil
}

func validWindowsAgentPipe(path string) bool {
	const prefix = `\\.\pipe\`
	if len(path) <= len(prefix) || len(path) > 256 || len(path) < len(prefix) || !equalWindowsPipePrefix(path, prefix) {
		return false
	}
	name := path[len(prefix):]
	if name == "" || len(name) > 200 {
		return false
	}
	for _, runeValue := range name {
		if runeValue == 0 || runeValue == '\r' || runeValue == '\n' || runeValue == '/' || runeValue == '\\' || runeValue == ':' || runeValue == '*' || runeValue == '?' || runeValue == '"' || runeValue == '<' || runeValue == '>' || runeValue == '|' {
			return false
		}
	}
	return true
}

func equalWindowsPipePrefix(value, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range prefix {
		left, right := value[index], prefix[index]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func isDelegableWindowsAgentPipe(path string) bool {
	if !validWindowsAgentPipe(path) {
		return false
	}
	name := path[len(`\\.\pipe\`):]
	return name == "openssh-ssh-agent" || len(name) > len("paperboat-ssh-agent-") && name[:len("paperboat-ssh-agent-")] == "paperboat-ssh-agent-"
}

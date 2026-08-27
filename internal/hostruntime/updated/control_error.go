package updated

import "strings"

const maxControlErrorMessage = 2048

// ControlError is a bounded diagnostic returned by the local managed updater.
// Code remains stable for automation; Message carries local recovery evidence
// so pb update does not collapse every signing, staging, or SCM failure into a
// generic check_failed string.
type ControlError struct {
	Code    string
	Message string
}

func (e *ControlError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func boundedControlErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Map(func(character rune) rune {
		if character == '\x00' || character == '\r' || character == '\n' || character < 0x20 && character != '\t' {
			return ' '
		}
		return character
	}, err.Error())
	if len(message) > maxControlErrorMessage {
		message = message[:maxControlErrorMessage]
	}
	return message
}

func validControlErrorMessage(message string) bool {
	if len(message) > maxControlErrorMessage {
		return false
	}
	for _, character := range message {
		if character == '\x00' || character == '\r' || character == '\n' || character < 0x20 && character != '\t' {
			return false
		}
	}
	return true
}

func validControlResponseError(status, code, message string) bool {
	if !validControlErrorMessage(message) {
		return false
	}
	if status == "error" {
		return code != ""
	}
	return code == "" && message == ""
}

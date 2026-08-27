package updated

import (
	"errors"
	"strings"
	"testing"
)

func TestBoundedControlErrorMessageIsSingleLineAndCapped(t *testing.T) {
	message := boundedControlErrorMessage(errors.New(strings.Repeat("x", maxControlErrorMessage+100) + "\r\nforged"))
	if len(message) != maxControlErrorMessage || strings.ContainsAny(message, "\x00\r\n") || !validControlErrorMessage(message) {
		t.Fatalf("message length=%d value=%q", len(message), message)
	}
}

func TestControlErrorIncludesCodeAndDiagnostic(t *testing.T) {
	err := (&ControlError{Code: "check_failed", Message: "invalid canonical service target"}).Error()
	if err != "check_failed: invalid canonical service target" {
		t.Fatalf("error=%q", err)
	}
}

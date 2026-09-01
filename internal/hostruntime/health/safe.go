package health

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	RedactedValue       = "[REDACTED]"
	maximumSummaryBytes = 256
	maximumRepairBytes  = 256
	maximumMessageBytes = 512
)

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var safeStringRedactions = []redactionRule{
	{regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----`), RedactedValue},
	{regexp.MustCompile(`(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*.*$`), RedactedValue},
	{regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`), RedactedValue},
	{regexp.MustCompile(`(?i)("(?:authorization|proxy_authorization|cookie|set_cookie|token|access_token|refresh_token|password|passwd|secret|api_key|client_secret|private_key|credential|credential_ref|credential_reference|secret_ref|token_ref|signed_url)"\s*:\s*)"[^"]*"`), `${1}"` + RedactedValue + `"`},
	{regexp.MustCompile(`(?i)((?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|token|access[_-]?token|refresh[_-]?token|password|passwd|secret|api[_-]?key|client[_-]?secret|private[_-]?key|credential(?:[_-]?(?:ref|reference))?|secret[_-]?ref|token[_-]?ref|signed[_-]?url)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), `${1}` + RedactedValue},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), RedactedValue},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), RedactedValue},
	{regexp.MustCompile(`\bgh[opusr]_[A-Za-z0-9]{20,}\b`), RedactedValue},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), RedactedValue},
	{regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]+`), RedactedValue},
	{regexp.MustCompile(`(?i)(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s,;]+`), RedactedValue},
	{regexp.MustCompile(`\b(?:account|actor|assignment|certificate|connector|correlation|device|domain|edge|host|operation|process|request|resource|route|session|tunnel)_[A-Za-z0-9_.:-]+\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`), RedactedValue},
}

// Redact returns a bounded, printable, secret-safe value for last-resort
// diagnostics. It never returns an error.
func Redact(value string) string {
	redacted, err := safeBoundedString(value, maximumMessageBytes, false)
	if err != nil {
		return RedactedValue
	}
	return redacted
}

// SafeString applies the health package's construction-time redaction policy
// with a caller-supplied byte bound.
func SafeString(value string, maximum int) (string, error) {
	return safeBoundedString(value, maximum, false)
}

func safeBoundedString(value string, maximum int, required bool) (string, error) {
	if maximum <= 0 || !utf8.ValidString(value) {
		return "", newError(ErrorInvalidString, "construct host health")
	}
	for _, rule := range safeStringRedactions {
		value = rule.pattern.ReplaceAllString(value, rule.replacement)
	}
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if required && value == "" {
		return "", newError(ErrorInvalidString, "construct host health")
	}
	if len(value) > maximum {
		value = value[:maximum]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value, nil
}

var correlationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func validCorrelationID(value string) bool { return correlationPattern.MatchString(value) }

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

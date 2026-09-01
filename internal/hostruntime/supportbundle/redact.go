package supportbundle

import (
	"regexp"
)

type redactionRule struct {
	re          *regexp.Regexp
	replacement string
}

var redactionRules = []redactionRule{
	{regexp.MustCompile(`(?is)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----`), RedactedValue},
	{regexp.MustCompile(`(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*:\s*).*$`), `${1}` + RedactedValue},
	{regexp.MustCompile(`(?i)("(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|x[-_]api[-_]key|x[-_]auth[-_]token|x[-_]csrf[-_]token|token|access[-_]token|refresh[-_]token|password|passwd|secret|api[-_]key|client[-_]secret|private[-_]key|credential|credential[-_]ref|credential[-_]reference|secret[-_]ref|token[-_]ref|signed[-_]url)"\s*:\s*)"[^"]*"`), `${1}"` + RedactedValue + `"`},
	{regexp.MustCompile(`(?i)((?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]api[-_]key|x[-_]auth[-_]token|x[-_]csrf[-_]token|token|access[-_]?token|refresh[-_]?token|password|passwd|secret|api[-_]?key|client[-_]?secret|private[-_]?key|credential(?:[-_]?(?:ref|reference))?|secret[-_]?ref|token[-_]?ref|signed[-_]?url)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), `${1}` + RedactedValue},
	{regexp.MustCompile(`(?i)([?&](?:token|access_token|refresh_token|api_key|key|signature|sig|credential|password|secret)=)[^&#\s]+`), `${1}` + RedactedValue},
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`), `${1}` + RedactedValue + `@`},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), RedactedValue},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), RedactedValue},
	{regexp.MustCompile(`\bgh[opusr]_[A-Za-z0-9]{20,}\b`), RedactedValue},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), RedactedValue},
	{regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`), RedactedValue},
	{regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]+`), RedactedValue},
	{regexp.MustCompile(`(?i)(?:/Users/|/home/|[A-Z]:\\Users\\)[^\s,;]+`), RedactedValue},
	{regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`), RedactedValue},
}

var sensitiveMetadataKey = regexp.MustCompile(`(?i)^(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|x[-_]api[-_]key|x[-_]auth[-_]token|x[-_]csrf[-_]token|token|access[-_]token|refresh[-_]token|password|passwd|secret|api[-_]key|client[-_]secret|private[-_]key|credential|credential[-_]ref|credential[-_]reference|secret[-_]ref|token[-_]ref|signed[-_]url)$`)

func redactString(value string) (string, int) {
	redactions := 0
	for _, rule := range redactionRules {
		matches := rule.re.FindAllStringIndex(value, -1)
		if len(matches) == 0 {
			continue
		}
		redactions += len(matches)
		value = rule.re.ReplaceAllString(value, rule.replacement)
	}
	return value, redactions
}

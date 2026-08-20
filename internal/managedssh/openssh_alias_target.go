package managedssh

import "strings"

type OpenSSHAliasTarget struct {
	Alias       string
	DisplayName string
	User        string
	Port        uint16
}

func openSSHHostPatterns(host, displayName, suffix string) string {
	patterns := host
	displayName = strings.TrimSpace(displayName)
	alias := strings.TrimSuffix(host, "."+suffix)
	// OpenSSH Host matching is case-sensitive. Preserve the display spelling
	// only when it is another casing of the authoritative alias; display names
	// are not SSH aliases and may be non-unique across machines.
	if displayName != alias && strings.EqualFold(displayName, alias) {
		patterns += " " + displayName + "." + suffix
	}
	return patterns
}

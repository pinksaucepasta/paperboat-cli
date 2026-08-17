package managedssh

import "strings"

func validAliasSuffix(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validAliasLabel(label) {
			return false
		}
	}
	return true
}

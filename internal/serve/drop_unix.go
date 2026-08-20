//go:build unix

package serve

import shlex "github.com/anmitsu/go-shlex"

func droppedFileCandidate(value string) (string, bool) {
	tokens, err := shlex.Split(value, true)
	returnCandidate := len(tokens) == 1 && err == nil
	if !returnCandidate {
		return "", false
	}
	return tokens[0], true
}

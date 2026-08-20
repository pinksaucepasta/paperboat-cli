//go:build !unix && !windows

package serve

import shlex "github.com/anmitsu/go-shlex"

func droppedFileCandidate(value string) (string, bool) {
	tokens, err := shlex.Split(value, true)
	if err != nil || len(tokens) != 1 {
		return "", false
	}
	return tokens[0], true
}

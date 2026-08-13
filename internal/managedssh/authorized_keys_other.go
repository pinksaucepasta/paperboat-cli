//go:build !darwin && !linux

package managedssh

import "errors"

type AuthorizedKeysResult struct {
	Changed bool
	Count   int
}

func ReconcileAuthorizedKeys(string, uint32, []string) (AuthorizedKeysResult, error) {
	return AuthorizedKeysResult{}, errors.New("managed SSH authorized_keys reconciliation is unsupported on this platform")
}

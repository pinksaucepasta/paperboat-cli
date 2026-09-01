//go:build !darwin && !linux

package environmentkey

import "errors"

func newPortableStore(PortableConfig, [32]byte) (SecretStore, error) {
	return nil, errors.Join(ErrUnavailable, errors.New("portable environment host-key storage is unavailable"))
}

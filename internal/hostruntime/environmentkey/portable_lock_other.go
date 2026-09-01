//go:build !darwin && !linux

package environmentkey

import "errors"

func lockPortablePath(string) (func() error, error) {
	return nil, errors.Join(ErrUnavailable, errors.New("portable environment host-key locking is unavailable"))
}

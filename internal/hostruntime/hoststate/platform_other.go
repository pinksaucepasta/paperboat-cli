//go:build !darwin && !linux && !windows

package hoststate

import "errors"

type processLock struct{}

func ensurePrivateDirectory(string) error             { return errors.ErrUnsupported }
func acquireProcessLock(string) (*processLock, error) { return nil, errors.ErrUnsupported }
func (*processLock) Close() error                     { return nil }
func readPrivateFile(string, int64) ([]byte, error)   { return nil, errors.ErrUnsupported }
func syncDirectory(string) error                      { return errors.ErrUnsupported }

//go:build !darwin && !linux && !windows

package tunnelcreatejournal

import "errors"

type processLock struct{}

func ensurePrivateDirectory(string) error             { return ErrInvalid }
func acquireProcessLock(string) (*processLock, error) { return nil, ErrInvalid }
func (*processLock) Close() error                     { return nil }
func readPrivateFile(string, int64) ([]byte, error)   { return nil, ErrInvalid }
func removePrivateFile(string) error                  { return ErrInvalid }
func syncDirectory(string) error                      { return errors.New("unsupported platform") }

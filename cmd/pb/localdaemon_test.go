package main

import (
	"context"
	"errors"
)

// A test binary cannot serve as the detached Paperboat daemon executable. In
// particular, registering pb.test with the platform service manager can start
// recursive test processes that retain files and named pipes after the test
// process exits. Command tests must provide an in-process local API server
// when they require one.
func init() {
	installLocalDaemonService = func(context.Context, string, string, string) error {
		return errors.New("local daemon installation is disabled during command tests")
	}
}

package service

import "time"

type ProcessNotifier struct{}

func NewProcessNotifier() (*ProcessNotifier, error)      { return &ProcessNotifier{}, nil }
func (*ProcessNotifier) WatchdogInterval() time.Duration { return 0 }
func (*ProcessNotifier) Starting() error                 { return nil }
func (*ProcessNotifier) Ready() error                    { return nil }
func (*ProcessNotifier) Degraded(string) error           { return nil }
func (*ProcessNotifier) Draining() error                 { return nil }
func (*ProcessNotifier) Stopping() error                 { return nil }
func (*ProcessNotifier) Watchdog() error                 { return nil }

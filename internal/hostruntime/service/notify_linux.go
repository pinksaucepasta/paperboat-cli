package service

import (
	"errors"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

type ProcessNotifier struct {
	watchdog time.Duration
}

func NewProcessNotifier() (*ProcessNotifier, error) {
	watchdog, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		return nil, err
	}
	return &ProcessNotifier{watchdog: watchdog}, nil
}

func (n *ProcessNotifier) WatchdogInterval() time.Duration {
	if n == nil || n.watchdog == 0 {
		return 0
	}
	return n.watchdog / 2
}

func (n *ProcessNotifier) Starting() error { return n.status("starting") }
func (n *ProcessNotifier) Ready() error    { return n.notify(daemon.SdNotifyReady + "\nSTATUS=ready") }
func (n *ProcessNotifier) Degraded(reason string) error {
	if !safeNotificationStatus(reason) {
		return ErrInvalidDefinition
	}
	return n.status("degraded: " + reason)
}
func (n *ProcessNotifier) Draining() error { return n.status("draining") }
func (n *ProcessNotifier) Stopping() error {
	return n.notify(daemon.SdNotifyStopping + "\nSTATUS=stopping")
}
func (n *ProcessNotifier) Watchdog() error { return n.notify(daemon.SdNotifyWatchdog) }

func (n *ProcessNotifier) status(value string) error { return n.notify("STATUS=" + value) }

func (n *ProcessNotifier) notify(state string) error {
	if n == nil {
		return errors.New("nil process notifier")
	}
	_, err := daemon.SdNotify(false, state)
	return err
}

func safeNotificationStatus(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}

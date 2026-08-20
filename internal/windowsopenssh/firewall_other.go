//go:build !windows

package windowsopenssh

import (
	"context"
	"time"
)

func snapshotFirewall(context.Context, Config) (FirewallSnapshot, error) {
	return FirewallSnapshot{CapturedAt: time.Now().UTC()}, nil
}
func disableOwnedFirewallRule(context.Context, Config, string) error { return nil }
func removeOwnedFirewallRule(context.Context, Config, string) error  { return nil }

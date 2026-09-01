//go:build darwin

package networkmonitor

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// SystemDNSFingerprint uses macOS SystemConfiguration's scutil DNS view.
// Normalized opaque lines make equivalent formatting/order changes stable
// while keeping all resolver details inside the hash boundary.
func SystemDNSFingerprint(ctx context.Context) ([32]byte, error) {
	if err := validateDNSContext(ctx); err != nil {
		return [32]byte{}, err
	}
	command := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns")
	output := &boundedBuffer{limit: maxDNSFingerprintInput}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return [32]byte{}, ctx.Err()
		}
		return [32]byte{}, fmt.Errorf("%w: scutil: %v", ErrDNSUnavailable, err)
	}
	if output.overflow {
		return [32]byte{}, ErrDNSUnavailable
	}
	lines := strings.Split(string(output.data), "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			normalized = append(normalized, line)
		}
	}
	sort.Strings(normalized)
	return hashDNSFingerprint([]byte(strings.Join(normalized, "\n")))
}

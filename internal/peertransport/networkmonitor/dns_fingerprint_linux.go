//go:build linux

package networkmonitor

import (
	"context"
	"fmt"
	"io"
	"os"
)

// SystemDNSFingerprint hashes the bounded Linux resolver configuration. The
// resolver file is read only inside this package and never leaves as an event,
// metric, error, or log value.
func SystemDNSFingerprint(ctx context.Context) ([32]byte, error) {
	if err := validateDNSContext(ctx); err != nil {
		return [32]byte{}, err
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: open resolver configuration: %v", ErrDNSUnavailable, err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxDNSFingerprintInput+1))
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: read resolver configuration: %v", ErrDNSUnavailable, err)
	}
	if len(contents) > maxDNSFingerprintInput {
		return [32]byte{}, ErrDNSUnavailable
	}
	return hashDNSFingerprint(contents)
}

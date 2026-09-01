//go:build !linux && !darwin && !windows

package networkmonitor

import "context"

// SystemDNSFingerprint deliberately fails closed on platforms without a
// native implementation. Callers may provide an audited DNSFingerprintSource
// through ConfigureDNS when platform support is added.
func SystemDNSFingerprint(ctx context.Context) ([32]byte, error) {
	if err := validateDNSContext(ctx); err != nil {
		return [32]byte{}, err
	}
	return [32]byte{}, ErrDNSUnavailable
}

package networkmonitor

import "crypto/sha256"

const maxDNSFingerprintInput = 64 << 10

func hashDNSFingerprint(input []byte) ([32]byte, error) {
	if len(input) == 0 || len(input) > maxDNSFingerprintInput {
		return [32]byte{}, ErrDNSUnavailable
	}
	return sha256.Sum256(input), nil
}

// boundedBuffer keeps command output bounded while still allowing the child
// process to exit normally. Its contents are only used as hash input.
type boundedBuffer struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b == nil || b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.overflow = true
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

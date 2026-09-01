package pty

// The PTY policy must accommodate the complete managed ENV Injection
// snapshot (128 variables / 256 KiB), explicit execution overrides, and the
// small runtime-owned base environment. The environment service validates the
// managed subset more narrowly before it reaches this boundary.
const (
	maximumProcessEnvironmentEntries    = 272
	maximumProcessEnvironmentEntryBytes = 128 + 1 + 32_767
	maximumProcessEnvironmentBytes      = 320 << 10
)

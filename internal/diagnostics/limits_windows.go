//go:build windows

package diagnostics

// MaximumRecordBytes bounds one diagnostic event on platforms where the
// durable disk recorder is not available. Event validation is shared with the
// Unix recorder and still needs the same wire-size limit.
const MaximumRecordBytes = 64 << 10

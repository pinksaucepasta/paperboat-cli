// Package buildinfo holds build-time metadata that release builds override via
// -ldflags. Keeping these as vars (not consts) lets the linker stamp them.
package buildinfo

// Version is the CLI version. Replaced by release builds.
var Version = "dev"

// ProtocolVersion is the control-plane contract understood by this binary.
var ProtocolVersion = "1"

// DefaultServerURL is the default paperboat-server base URL. Replaced by
// release builds; empty requires server_url or --server at runtime.
var DefaultServerURL = ""

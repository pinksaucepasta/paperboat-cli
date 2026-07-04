// Package buildinfo holds build-time metadata that release builds override via
// -ldflags. Keeping these as vars (not consts) lets the linker stamp them.
package buildinfo

// Version is the CLI version. Replaced by release builds.
var Version = "dev"

// DefaultServerURL is the default paperboat-server base URL. Replaced by
// release builds; empty means "not configured, use local dev stub".
var DefaultServerURL = ""

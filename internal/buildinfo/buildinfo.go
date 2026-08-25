// Package buildinfo holds build-time metadata that release builds override via
// -ldflags. Keeping these as vars (not consts) lets the linker stamp them.
package buildinfo

// Version is the CLI version. Replaced by release builds.
var Version = "dev"

// WindowsPublisher is the required Authenticode signer subject fragment for
// Windows release components. Release builds replace it with the legal
// publisher name encoded in the signing certificate.
var WindowsPublisher = "Paperboat"

// Commit is the source revision. Replaced by release builds.
var Commit = "unknown"

// ProtocolVersion is the control-plane contract understood by this binary.
var ProtocolVersion = "1"

// DefaultServerURL is the first-party Paperboat control plane. Private builds
// may replace it with -ldflags, but official binaries work without setup.
var DefaultServerURL = "https://api.pprbt.dev"

// DefaultReleaseURL is the HTTPS origin serving the signed TUF repository.
// Release builds replace it with the production release origin.
var DefaultReleaseURL = ""

// WindowsArtifactRole is stamped into each privileged Windows service
// artifact. It prevents a service binary from acting as the general CLI or a
// different privileged role even if its command line is changed.
var WindowsArtifactRole = ""

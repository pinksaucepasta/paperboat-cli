//go:build windows

package windowsopenssh

// platformServiceSID derives the SID that SCM assigns to PaperboatHostd. SCM's
// service SID is deterministic, so it is available before the service is first
// registered. The runtime must be able to read only the public host key;
// granting this service SID avoids broad filesystem access.
func platformServiceSID() string {
	return deriveServiceSID("PaperboatHostd")
}

//go:build windows

package windowsopenssh

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformServiceSID resolves the SID assigned by SCM to the PaperboatHostd
// service. The runtime must be able to read only the public host key; granting
// this service SID avoids giving the service account broad filesystem access.
func platformServiceSID() string {
	name, err := windows.UTF16PtrFromString("NT SERVICE\\PaperboatHostd")
	if err != nil {
		return ""
	}
	var sidLen, domainLen, use uint32
	err = windows.LookupAccountName(nil, name, nil, &sidLen, nil, &domainLen, &use)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || sidLen == 0 {
		return ""
	}
	sidBytes := make([]byte, sidLen)
	domain := make([]uint16, domainLen)
	if err := windows.LookupAccountName(nil, name, (*windows.SID)(unsafe.Pointer(&sidBytes[0])), &sidLen, &domain[0], &domainLen, &use); err != nil {
		return ""
	}
	sid := (*windows.SID)(unsafe.Pointer(&sidBytes[0]))
	if !sid.IsValid() {
		return ""
	}
	return sid.String()
}

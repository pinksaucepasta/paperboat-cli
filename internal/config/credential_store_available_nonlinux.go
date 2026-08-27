//go:build !linux

package config

// Non-Linux platforms use a native credential backend whose availability is
// handled by the backend itself. Linux is the only platform with a common
// headless-session failure that can be detected before bootstrap writes state.
func CredentialStoreAvailable() bool { return true }

//go:build !darwin && !linux && !windows

package config

func purgeCredentialStore() error { return ErrCredentialStoreUnavailable }

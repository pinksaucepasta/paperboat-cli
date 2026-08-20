//go:build !windows

package windowsopenssh

func lockAuthorizedKeys(string) (func(), error) { return func() {}, nil }

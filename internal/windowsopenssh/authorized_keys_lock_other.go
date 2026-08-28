//go:build !windows

package windowsopenssh

import "context"

func lockAuthorizedKeys(context.Context, string) (func(), error) { return func() {}, nil }

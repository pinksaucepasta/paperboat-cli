//go:build !windows

package main

import "context"

func setupPlatformHostPrerequisites(context.Context) (uint16, error) { return 0, nil }

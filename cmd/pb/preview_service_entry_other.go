//go:build !windows

package main

import "context"

func enterWindowsPreviewService(context.Context, string, string) (bool, error) { return false, nil }

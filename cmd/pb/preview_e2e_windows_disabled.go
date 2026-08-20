//go:build !windows || !paperboat_native_e2e

package main

import "context"

func runWindowsPreviewNativeE2E(context.Context, string, string) (bool, error) { return false, nil }

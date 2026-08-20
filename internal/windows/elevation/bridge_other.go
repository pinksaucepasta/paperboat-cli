//go:build !windows

package elevation

import "context"

func RunRuntimeService(context.Context, string, string, any) error { return ErrUnsupported }

func RunOpenSSH(context.Context, string, string) error { return ErrUnsupported }

func IsCurrentProcessElevated() bool { return false }

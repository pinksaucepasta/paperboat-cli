//go:build !windows

package windowsopenssh

import "context"

func collectLoopbackHealth(context.Context, Config, Result) (ServiceHealth, error) {
	return ServiceHealth{}, ErrInstallerUnavailable
}

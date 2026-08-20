//go:build !windows

package windowsopenssh

import (
	"context"
)

func qualifyNative(context.Context, Config, Result) (QualificationReport, error) {
	return QualificationReport{}, ErrInstallerUnavailable
}

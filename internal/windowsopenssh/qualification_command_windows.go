//go:build windows

package windowsopenssh

import (
	"context"
	"path/filepath"
)

type qualificationCommandResult struct {
	Output   []byte
	ExitCode int
}

func runQualificationCommand(ctx context.Context, config Config, path string, args ...string) (qualificationCommandResult, error) {
	if ctx == nil || config.Runner == nil || !filepath.IsAbs(path) {
		return qualificationCommandResult{ExitCode: -1}, ErrInvalidConfig
	}
	commandCtx, cancel := context.WithTimeout(ctx, qualificationCommandTimeout)
	defer cancel()
	output, err := config.Runner.Run(commandCtx, path, args...)
	result := qualificationCommandResult{Output: output, ExitCode: qualificationExitCode(err)}
	if commandCtx.Err() != nil {
		return result, commandCtx.Err()
	}
	return result, err
}

//go:build !darwin && !linux && !windows

package hostruntimeentry

import (
	"context"
	"errors"
	"net/http"
)

var ErrUnsupported = errors.New("machine runtime services are supported only on macOS and Linux")

type ConfigWorkerConfig struct {
	ControlURL, StateRoot, HomeRoot, ChezmoiBinary string
	RepositoryHosts                                []string
	Transport                                      http.RoundTripper
}

func RunConfigWorker(context.Context, ConfigWorkerConfig) error { return ErrUnsupported }

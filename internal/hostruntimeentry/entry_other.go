//go:build !darwin && !linux

package hostruntimeentry

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
)

var ErrUnsupported = errors.New("machine runtime services are supported only on macOS and Linux")

type ConfigWorkerConfig struct {
	ControlURL, StateRoot, HomeRoot, ChezmoiBinary string
	RepositoryHosts                                []string
	Transport                                      http.RoundTripper
}

type PreviewWorkerConfig struct {
	ControlURL, StateRoot, Name, DescriptorPath, ServiceDefinition string
	Port                                                           uint16
	Duration                                                       time.Duration
	Indefinite                                                     bool
	ExpiresAt                                                      *time.Time
	Transport                                                      http.RoundTripper
	Ready                                                          func(preview.ControlRecord) error
}

func RunConfigWorker(context.Context, ConfigWorkerConfig) error   { return ErrUnsupported }
func RunPreviewWorker(context.Context, PreviewWorkerConfig) error { return ErrUnsupported }
func InstallPreviewService(context.Context, string, string, string, uint16, *time.Time, bool) error {
	return ErrUnsupported
}
func WaitPreviewServiceReady(context.Context, string, string) (preview.ControlRecord, error) {
	return preview.ControlRecord{}, ErrUnsupported
}

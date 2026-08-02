//go:build !darwin && !linux

package hostruntimeentry

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
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
	SourceKind, OwnerMode                                          string
}

type ServeWorkerConfig struct {
	ControlURL, StateRoot, Name, DescriptorPath, ServiceDefinition string
	ExpiresAt                                                      *time.Time
	Indefinite                                                     bool
	Transport                                                      http.RoundTripper
	ServiceRunner                                                  hostservice.Runner
	PreviewRunner                                                  servepkg.PreviewRunner
}

func RunConfigWorker(context.Context, ConfigWorkerConfig) error   { return ErrUnsupported }
func RunPreviewWorker(context.Context, PreviewWorkerConfig) error { return ErrUnsupported }
func RunServeWorker(context.Context, ServeWorkerConfig) error     { return ErrUnsupported }
func InstallPreviewService(context.Context, string, string, string, uint16, *time.Time, bool) error {
	return ErrUnsupported
}
func InstallServeService(context.Context, string, string, string, servepkg.Source, bool, *time.Time, bool) error {
	return ErrUnsupported
}
func WaitPreviewServiceReady(context.Context, string, string) (preview.ControlRecord, error) {
	return preview.ControlRecord{}, ErrUnsupported
}
func RemovePreviewService(context.Context, string, string) error { return ErrUnsupported }
func RemoveAllPreviewServices(context.Context, string) error     { return ErrUnsupported }

//go:build darwin || linux || windows

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/configsync"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/machinecontrol"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

type productionConfigSyncConfig struct {
	ControlURL      string
	ControlHost     string
	RepositoryHosts []string
	HomeRoot        string
	StateRoot       string
	ChezmoiBinary   string
	Identities      configsync.TokenSource
	Proofs          configsync.ProofSource
	OperationID     configsync.OperationIDSource
	Transport       http.RoundTripper
}

type ProductionConfigWorkerConfig struct {
	ControlURL      string
	StateRoot       string
	HomeRoot        string
	ChezmoiBinary   string
	RepositoryHosts []string
	Transport       http.RoundTripper
}

func RunProductionConfigWorker(ctx context.Context, config ProductionConfigWorkerConfig) error {
	controlURL, err := url.Parse(strings.TrimSpace(config.ControlURL))
	if err != nil || controlURL.Scheme != "https" || controlURL.Hostname() == "" || !filepath.IsAbs(config.StateRoot) || !filepath.IsAbs(config.HomeRoot) {
		return ErrProductionInvalid
	}
	identities, err := machinecontrol.NewSource(machinecontrol.Config{ControlURL: controlURL.String(), StateRoot: config.StateRoot, Transport: config.Transport})
	if err != nil {
		return err
	}
	service, err := newProductionConfigSync(productionConfigSyncConfig{
		ControlURL: controlURL.String(), ControlHost: controlURL.Hostname(), RepositoryHosts: config.RepositoryHosts,
		HomeRoot: config.HomeRoot, StateRoot: config.StateRoot, ChezmoiBinary: config.ChezmoiBinary,
		Identities: identities, Proofs: identities, OperationID: randomProductionOperationID, Transport: config.Transport,
	})
	if err != nil {
		return err
	}
	return service.Start(ctx)
}

func randomProductionOperationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "config-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func newProductionConfigSync(config productionConfigSyncConfig) (*configsync.Supervisor, error) {
	client, err := configsync.NewControlClient(configsync.ControlClientConfig{
		BaseURL: config.ControlURL, AllowedHosts: []string{config.ControlHost},
		RepositoryHosts: config.RepositoryHosts, Identities: config.Identities,
		Proofs: config.Proofs, OperationID: config.OperationID, Transport: config.Transport,
	})
	if err != nil {
		return nil, err
	}
	return configsync.NewSupervisor(configsync.SupervisorConfig{
		Credentials: client,
		Factory: func(ctx context.Context, credential configsync.Credential) (configsync.Runtime, error) {
			descriptor, err := client.RuntimeDescriptor(ctx)
			if err != nil {
				return nil, err
			}
			if descriptor.AssignmentID != credential.AssignmentID ||
				descriptor.EnvironmentID != credential.EnvironmentID ||
				descriptor.MachineID != credential.MachineID ||
				descriptor.WarningRevision != credential.WarningRevision {
				return nil, configsync.ErrAuthorization
			}
			descriptor, err = protectConfigSyncRuntimeState(descriptor, config.HomeRoot, config.StateRoot)
			if err != nil {
				return nil, err
			}
			hash := sha256.Sum256([]byte(descriptor.AssignmentID))
			assignmentRoot := filepath.Join(config.StateRoot, "config-sync", hex.EncodeToString(hash[:16]))
			if err := os.MkdirAll(assignmentRoot, 0o700); err != nil {
				return nil, err
			}
			assignmentRoot, err = filepath.EvalSymlinks(assignmentRoot)
			if err != nil {
				return nil, err
			}
			transport := config.Transport
			if transport == nil {
				transport = httptransport.Default()
			}
			chezmoiBinary, err := ensureChezmoi(
				ctx, config.ChezmoiBinary, assignmentRoot,
				&http.Client{Transport: transport, Timeout: 2 * time.Minute},
			)
			if err != nil {
				return nil, err
			}
			repositoryRoot := filepath.Join(assignmentRoot, "repository")
			reconciler, err := configsync.NewPlaintextWorkspaceReconciler(configsync.WorkspaceReconcilerConfig{
				HomeRoot: config.HomeRoot, StateRoot: assignmentRoot, Descriptor: descriptor,
				Resolutions: client, ChezmoiBinary: chezmoiBinary,
			})
			if err != nil {
				return nil, err
			}
			repository, err := configsync.NewGitRepository(configsync.GitRepositoryConfig{
				Root: repositoryRoot, Access: client, Reconciler: reconciler,
			})
			if err != nil {
				return nil, err
			}
			publisher, err := configsync.NewPublisher(configsync.PublisherConfig{
				Authority: client, Repository: repository,
			})
			if err != nil {
				return nil, err
			}
			return configsync.NewEngine(configsync.EngineConfig{
				HomeRoot: config.HomeRoot, Descriptor: descriptor, Syncer: publisher, Statuses: client,
				Diagnostics: reconciler, Manifest: reconciler,
				StatusPath: filepath.Join(assignmentRoot, "status.json"),
			})
		},
	})
}

func protectConfigSyncRuntimeState(
	descriptor configsync.RuntimeDescriptor,
	homeRoot string,
	stateRoot string,
) (configsync.RuntimeDescriptor, error) {
	relative, err := filepath.Rel(homeRoot, stateRoot)
	if err != nil {
		return configsync.RuntimeDescriptor{}, errors.Join(ErrProductionInvalid, err)
	}
	if relative == "." {
		return configsync.RuntimeDescriptor{}, errors.Join(ErrProductionInvalid, errors.New("config sync state root cannot be the managed home"))
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return descriptor, nil
	}
	relative = filepath.ToSlash(relative)
	for _, existing := range descriptor.Policy.RuntimeExclusionRoots {
		if existing == relative {
			return descriptor, nil
		}
	}
	descriptor.Policy.RuntimeExclusionRoots = append(descriptor.Policy.RuntimeExclusionRoots, relative)
	return descriptor, nil
}

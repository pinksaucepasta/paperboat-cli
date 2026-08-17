//go:build darwin || linux

// Package updated runs the mandatory, worker-only Paperboat update scheduler.
// It is separate from hostd: hostd keeps workloads alive, while updated owns
// verified artifact staging and asks a fenced child worker to take over.
package updated

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

var ErrInvalidConfig = errors.New("invalid paperboat-updated configuration")

type Config struct {
	StateRoot       string
	RuntimeCurrent  string
	RuntimeRollback string
	RuntimeStaged   string
	Active          workerupdate.Release
	WorkerUID       int
	WorkerGID       int
	SocketPath      string
	Token           []byte
	RepositoryURL   string
	MachineID       string
	Health          workerupdate.HealthChecker
}

type Service struct {
	manager   *workerupdate.Manager
	source    workerupdate.TUFSource
	scheduler *autoupdate.Scheduler
}

func New(config Config) (*Service, error) {
	if !filepath.IsAbs(config.StateRoot) || config.WorkerUID <= 0 || config.WorkerGID < 0 || len(config.Token) != 32 || config.SocketPath == "" || config.RepositoryURL == "" || config.MachineID == "" || config.Health == nil {
		return nil, ErrInvalidConfig
	}
	if err := secureRoot(config.StateRoot); err != nil {
		return nil, err
	}
	for _, path := range []string{filepath.Join(config.StateRoot, "tuf", "index"), filepath.Join(config.StateRoot, "tuf", "targets")} {
		if err := secureRoot(path); err != nil {
			return nil, err
		}
	}
	source := workerupdate.TUFSource{RepositoryURL: config.RepositoryURL, StateRoot: filepath.Join(config.StateRoot, "tuf"), MachineID: config.MachineID}
	client, err := hostdproto.NewClient(config.SocketPath, config.Token, 5*time.Second)
	if err != nil {
		return nil, err
	}
	manager, err := workerupdate.New(workerupdate.Config{StatePath: filepath.Join(config.StateRoot, "transaction.json"), RuntimeCurrent: config.RuntimeCurrent, RuntimeRollback: config.RuntimeRollback, RuntimeStaged: config.RuntimeStaged, Active: config.Active, OwnerUID: 0, OwnerGID: 0, WorkerUID: config.WorkerUID, WorkerGID: config.WorkerGID, HostdEndpoint: config.SocketPath, Capability: config.Token, Fetcher: source, Starter: workerupdate.ExecStarter{}, Hostd: client, Health: config.Health, MonitorWindow: 10 * time.Minute, HealthInterval: time.Second})
	if err != nil {
		return nil, err
	}
	scheduler, err := manager.MandatoryScheduler(source.Resolve, nil)
	if err != nil {
		return nil, err
	}
	return &Service{manager: manager, source: source, scheduler: scheduler}, nil
}

func (s *Service) Run(ctx context.Context) error {
	if s == nil || s.manager == nil || s.scheduler == nil {
		return ErrInvalidConfig
	}
	if err := s.manager.Recover(ctx); err != nil {
		return err
	}
	return s.scheduler.Run(ctx)
}

// UpdateNow is the control-plane/manual path. It bypasses the signed cohort
// delay only; TUF verification, revocation, compatibility, and continuity
// checks remain exactly the same as background activation.
func (s *Service) UpdateNow(ctx context.Context) (workerupdate.Result, error) {
	if s == nil || s.manager == nil {
		return workerupdate.Result{}, ErrInvalidConfig
	}
	return s.manager.Check(ctx, s.source.ResolveManual)
}

func (s *Service) Snapshot() autoupdate.Observation {
	if s == nil || s.scheduler == nil {
		return autoupdate.Observation{}
	}
	return s.scheduler.Snapshot()
}

// HTTPHealth is a bounded local hostd readiness check. The endpoint must be a
// fixed loopback URL supplied by the service definition, not a release index
// or user-controlled redirect. It is evaluated on every hostd heartbeat during
// the monitoring hold, so a merely fenced but unhealthy worker cannot commit.
type HTTPHealth struct {
	Endpoint string
	Client   *http.Client
}

func (h HTTPHealth) Check(ctx context.Context, status hostdproto.Status, _ workerupdate.Release) error {
	if status.State != hostdproto.StateActive || status.WorkerID == "" || status.Epoch == 0 || status.LastHeartbeatUnixMilli == 0 || time.Since(time.UnixMilli(status.LastHeartbeatUnixMilli)) > 15*time.Second {
		return ErrInvalidConfig
	}
	parsed, err := url.Parse(h.Endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/healthz" || net.ParseIP(parsed.Hostname()) == nil || !net.ParseIP(parsed.Hostname()).IsLoopback() {
		return ErrInvalidConfig
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.Endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var body struct {
		Live bool `json:"live"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body) != nil || !body.Live {
		return ErrInvalidConfig
	}
	return nil
}

func secureRoot(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrInvalidConfig
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != 0 {
		return ErrInvalidConfig
	}
	return nil
}

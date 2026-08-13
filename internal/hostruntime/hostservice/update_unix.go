//go:build darwin || linux

package hostservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
)

var (
	ErrUpdateInvalid  = errors.New("privileged update is invalid")
	ErrUpdateRollback = errors.New("privileged update rollback failed")
)

const updateJournalSchemaV1 = "paperboat.host-update/v1"

type updateFetcher interface {
	Fetch(context.Context, bootstrap.ArtifactTarget, string) (string, error)
}

type updateServices interface {
	RestartWorker(context.Context) error
	RestartHost()
}

type updateHealth interface {
	Check(context.Context, string) error
}

type UpdateConfig struct {
	StateRoot      string
	BinaryPath     string
	CurrentVersion string
	ListenAddress  string
}

type UpdateManager struct {
	mu        sync.Mutex
	config    UpdateConfig
	ownerUID  int
	fetcher   updateFetcher
	services  updateServices
	health    updateHealth
	journal   string
	current   string
	rollbacks string
}

type updateJournal struct {
	Schema          string    `json:"schema"`
	Stage           string    `json:"stage"`
	Version         string    `json:"version"`
	PreviousVersion string    `json:"previous_version"`
	Staged          string    `json:"staged,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func NewUpdateManager(config UpdateConfig) (*UpdateManager, error) {
	client := &http.Client{Transport: httptransport.Default(), Timeout: 2 * time.Minute, CheckRedirect: secureUpdateRedirect}
	manager := &UpdateManager{
		config: config, ownerUID: 0, fetcher: artifactUpdateFetcher{client: client},
		services: platformUpdateServices{}, health: HTTPUpdateHealth{Address: config.ListenAddress},
		journal: filepath.Join(config.StateRoot, "update-journal.json"), current: filepath.Join(config.StateRoot, "update-current.json"), rollbacks: filepath.Join(config.StateRoot, "update-rollbacks.json"),
	}
	if err := manager.validate(); err != nil {
		return nil, err
	}
	if err := manager.recover(context.Background()); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *UpdateManager) Activate(ctx context.Context, artifact bootstrap.ArtifactTarget) (string, error) {
	if os.Geteuid() != 0 {
		return "", ErrUpdateInvalid
	}
	return m.activate(ctx, artifact)
}

func (m *UpdateManager) activate(ctx context.Context, artifact bootstrap.ArtifactTarget) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := verifyUpdate(m.config, artifact); err != nil {
		return "", err
	}
	comparison := compareReleaseVersion(artifact.Version, m.config.CurrentVersion)
	if comparison == 0 {
		entry, journalErr := m.loadJournal()
		if journalErr == nil && entry.Stage == "committed" && entry.Version == artifact.Version && verifyInstalledArtifact(m.config.BinaryPath, artifact, m.ownerUID) == nil {
			return artifact.Version, nil
		}
		return "", ErrUpdateInvalid
	}
	if comparison < 0 {
		return "", ErrUpdateInvalid
	}
	staged, err := m.fetcher.Fetch(ctx, artifact, filepath.Join(m.config.StateRoot, "tuf"))
	if err != nil {
		return "", err
	}
	defer os.Remove(staged)
	if binarytarget.Validate(staged, artifact.Platform, artifact.Architecture) != nil {
		return "", ErrUpdateInvalid
	}
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "staged", Version: artifact.Version, PreviousVersion: m.config.CurrentVersion, Staged: staged, UpdatedAt: time.Now().UTC()}
	if err := m.writeJournal(entry); err != nil {
		return "", err
	}
	entry.Stage, entry.UpdatedAt = "activating", time.Now().UTC()
	if err := m.writeJournal(entry); err != nil {
		return "", err
	}
	if err := replaceUpdateBinary(m.config.BinaryPath, staged, m.ownerUID); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	entry.Staged, entry.Stage, entry.UpdatedAt = "", "checking", time.Now().UTC()
	if err := m.writeJournal(entry); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	if err := m.services.RestartWorker(ctx); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	if err := m.health.Check(ctx, artifact.Version); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	if err := m.writeCurrent(artifact.Version); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	entry.Stage, entry.UpdatedAt = "committed", time.Now().UTC()
	if err := m.writeJournal(entry); err != nil {
		return "", errors.Join(err, m.rollback(ctx))
	}
	if err := m.finalizePrevious(); err != nil {
		return "", err
	}
	m.config.CurrentVersion = artifact.Version
	m.services.RestartHost()
	return artifact.Version, nil
}

func (m *UpdateManager) validate() error {
	if !filepath.IsAbs(m.config.StateRoot) {
		return fmt.Errorf("%w: state root is not absolute", ErrUpdateInvalid)
	}
	if !filepath.IsAbs(m.config.BinaryPath) {
		return fmt.Errorf("%w: binary path is not absolute", ErrUpdateInvalid)
	}
	if !validReleaseVersion(m.config.CurrentVersion) {
		return fmt.Errorf("%w: current version %q is invalid", ErrUpdateInvalid, m.config.CurrentVersion)
	}
	if m.config.ListenAddress == "" {
		return fmt.Errorf("%w: health listen address is empty", ErrUpdateInvalid)
	}
	for _, path := range []string{m.config.StateRoot, filepath.Dir(m.config.BinaryPath)} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%w: inspect directory %s: %v", ErrUpdateInvalid, path, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is not a real directory", ErrUpdateInvalid, path)
		}
		if owner := fileOwnerUID(info); owner != m.ownerUID {
			return fmt.Errorf("%w: directory %s owner is %d, want %d", ErrUpdateInvalid, path, owner, m.ownerUID)
		}
	}
	for _, path := range []string{m.config.BinaryPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%w: inspect binary %s: %v", ErrUpdateInvalid, path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is not a real regular file", ErrUpdateInvalid, path)
		}
		if owner := fileOwnerUID(info); owner != m.ownerUID {
			return fmt.Errorf("%w: binary %s owner is %d, want %d", ErrUpdateInvalid, path, owner, m.ownerUID)
		}
	}
	return nil
}

func verifyUpdate(config UpdateConfig, artifact bootstrap.ArtifactTarget) error {
	if bootstrap.VerifyArtifactTarget(artifact) != nil {
		return ErrUpdateInvalid
	}
	if artifact.Platform != runtime.GOOS || artifact.Architecture != runtime.GOARCH {
		return ErrUpdateInvalid
	}
	return nil
}

func verifyInstalledArtifact(path string, manifest bootstrap.ArtifactTarget, ownerUID int) error {
	if err := safeUpdateRegular(path, ownerUID); err != nil {
		return err
	}
	if binarytarget.Validate(path, manifest.Platform, manifest.Architecture) != nil {
		return ErrUpdateInvalid
	}
	return nil
}

func replaceUpdateBinary(current, staged string, ownerUID int) error {
	rollback := current + ".rollback"
	if err := safeUpdateRegular(current, ownerUID); err != nil {
		return err
	}
	if err := safeUpdateRegular(staged, ownerUID); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	if err := os.Remove(rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=host-updater reason=current-binary-rollback-stage
	if err := os.Rename(current, rollback); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=host-updater reason=verified-binary-activation
	if err := os.Rename(staged, current); err != nil {
		//paperboat:allow-source-policy atomic-replacement owner=host-updater reason=activation-failure-rollback
		_ = os.Rename(rollback, current)
		return err
	}
	return syncUpdateDirectory(filepath.Dir(current))
}

func (m *UpdateManager) rollback(ctx context.Context) error {
	return m.rollbackTo(ctx, m.config.CurrentVersion, true)
}

func (m *UpdateManager) rollbackTo(ctx context.Context, version string, restartWorker bool) error {
	if !validReleaseVersion(version) {
		return fmt.Errorf("%w: rollback version %q is invalid", ErrUpdateRollback, version)
	}
	var result error
	for _, current := range []string{m.config.BinaryPath} {
		rollback := current + ".rollback"
		if _, err := os.Lstat(rollback); err == nil {
			if removeErr := os.Remove(current); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, removeErr)
				continue
			}
			//paperboat:allow-source-policy atomic-replacement owner=host-updater reason=health-failure-rollback
			if renameErr := os.Rename(rollback, current); renameErr != nil {
				result = errors.Join(result, renameErr)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	if result == nil {
		result = errors.Join(result, m.writeCurrent(version))
		if restartWorker {
			result = errors.Join(result, m.services.RestartWorker(ctx))
		}
		result = errors.Join(result, os.Remove(m.journal))
	}
	if result != nil {
		return fmt.Errorf("%w: %v", ErrUpdateRollback, result)
	}
	if err := m.incrementRollbackCount(); err != nil {
		return fmt.Errorf("%w: %v", ErrUpdateRollback, err)
	}
	return nil
}

func (m *UpdateManager) RollbackCount() uint64 {
	body, err := os.ReadFile(m.rollbacks)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	var value struct {
		Schema string `json:"schema"`
		Count  uint64 `json:"count"`
	}
	if err != nil || json.Unmarshal(body, &value) != nil || value.Schema != "paperboat.host-update-rollbacks/v1" {
		return 0
	}
	return value.Count
}

// UpdateHealth exposes only a bounded category. Update details remain in the
// root-owned journal and never cross the host-service boundary.
func (m *UpdateManager) UpdateHealth() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.RollbackCount() > 1 {
		return "recovery_required"
	}
	entry, err := m.loadJournal()
	if errors.Is(err, os.ErrNotExist) {
		return "healthy"
	}
	if err != nil {
		return "recovery_required"
	}
	if entry.Stage == "committed" {
		return "healthy"
	}
	return "recovery_required"
}

func (m *UpdateManager) incrementRollbackCount() error {
	value := struct {
		Schema string `json:"schema"`
		Count  uint64 `json:"count"`
	}{"paperboat.host-update-rollbacks/v1", m.RollbackCount() + 1}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicRootWrite(m.rollbacks, body)
}

func (m *UpdateManager) recover(ctx context.Context) error {
	entry, err := m.loadJournal()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if entry.Stage == "committed" {
		if err := m.finalizePrevious(); err != nil {
			return err
		}
		// A committed activation already passed worker health before the journal
		// was advanced. The privileged listener is not running while this
		// constructor executes, so probing it here would deterministically fail
		// every first restart and incorrectly roll back a healthy binary.
		if m.config.CurrentVersion == entry.Version {
			return nil
		}
		// A root-owned out-of-band replacement supersedes the completed
		// transaction. Keep the running build authoritative and discard only the
		// stale transaction metadata.
		if err := errors.Join(m.writeCurrent(m.config.CurrentVersion), os.Remove(m.journal)); err != nil {
			return err
		}
		return nil
	}
	for _, staged := range []string{entry.Staged} {
		if staged != "" && safeUpdateStaged(staged, filepath.Dir(m.config.BinaryPath)) {
			_ = os.Remove(staged)
		}
	}
	if entry.Stage == "staged" {
		return os.Remove(m.journal)
	}
	// The service manager is already starting the worker during boot. A nested
	// restart from this constructor races that transaction and can make the
	// privileged service fail once before systemd retries it. Restore durable
	// state here; live activation rollback still restarts the running worker.
	return m.rollbackTo(ctx, entry.PreviousVersion, false)
}

func (m *UpdateManager) finalizePrevious() error {
	for _, current := range []string{m.config.BinaryPath} {
		rollback, previous := current+".rollback", current+".previous"
		if _, err := os.Lstat(rollback); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		//paperboat:allow-source-policy atomic-replacement owner=host-updater reason=verified-previous-retention
		if err := os.Rename(rollback, previous); err != nil {
			return err
		}
		if err := syncUpdateDirectory(filepath.Dir(current)); err != nil {
			return err
		}
	}
	return nil
}

func (m *UpdateManager) writeJournal(entry updateJournal) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return atomicRootWrite(m.journal, body)
}

func (m *UpdateManager) loadJournal() (updateJournal, error) {
	body, err := os.ReadFile(m.journal)
	if err != nil {
		return updateJournal{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var entry updateJournal
	var extra any
	if decoder.Decode(&entry) != nil || decoder.Decode(&extra) != io.EOF || entry.Schema != updateJournalSchemaV1 || !validReleaseVersion(entry.Version) || !validReleaseVersion(entry.PreviousVersion) || compareReleaseVersion(entry.Version, entry.PreviousVersion) <= 0 || !containsString([]string{"staged", "activating", "checking", "committed"}, entry.Stage) {
		return updateJournal{}, ErrUpdateInvalid
	}
	return entry, nil
}

func (m *UpdateManager) writeCurrent(version string) error {
	body, _ := json.Marshal(struct {
		Schema  string `json:"schema"`
		Version string `json:"version"`
	}{"paperboat.host-update-current/v1", version})
	return atomicRootWrite(m.current, body)
}

type artifactUpdateFetcher struct{ client *http.Client }

func (f artifactUpdateFetcher) Fetch(ctx context.Context, manifest bootstrap.ArtifactTarget, directory string) (string, error) {
	return bootstrap.FetchVerifiedArtifact(ctx, manifest, directory, f.client)
}

type platformUpdateServices struct{}

func (platformUpdateServices) RestartWorker(ctx context.Context) error {
	if runtime.GOOS == "linux" {
		return exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "paperboat-runtime-host.service").Run()
	}
	return exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "-k", "system/com.pinksaucepasta.paperboat.runtime-host").Run()
}

func (platformUpdateServices) RestartHost() {
	go func() {
		// Let the activation response flush before this process replaces itself.
		//paperboat:allow-source-policy sleep owner=runtime-update reason=flush-activation-response-before-self-restart
		time.Sleep(2 * time.Second)
		if runtime.GOOS == "linux" {
			_ = exec.Command("/usr/bin/systemctl", "restart", "--no-block", "paperboat-runtime-privileged.service").Run()
			return
		}
		_ = exec.Command("/bin/launchctl", "kickstart", "-k", "system/com.pinksaucepasta.paperboat.runtime-privileged").Run()
	}()
}

type HTTPUpdateHealth struct{ Address string }

func (h HTTPUpdateHealth) Check(ctx context.Context, version string) error {
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		request, _ := http.NewRequestWithContext(deadline, http.MethodGet, "http://"+h.Address+"/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			var value struct {
				Live    bool   `json:"live"`
				Version string `json:"version"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&value)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && value.Live && value.Version == version {
				return nil
			}
		}
		select {
		case <-deadline.Done():
			return deadline.Err()
		case <-time.After(time.Second):
		}
	}
}

func secureUpdateRedirect(request *http.Request, via []*http.Request) error {
	if len(via) > 5 || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Hostname() == "" {
		return ErrUpdateInvalid
	}
	return nil
}

func atomicRootWrite(path string, body []byte) error {
	return atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: os.Geteuid(), OwnerGID: -1})
}

func safeUpdateRegular(path string, ownerUID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect %s: %v", ErrUpdateInvalid, path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is not a real regular file", ErrUpdateInvalid, path)
	}
	if owner := fileOwnerUID(info); owner != ownerUID {
		return fmt.Errorf("%w: %s owner is %d, want %d", ErrUpdateInvalid, path, owner, ownerUID)
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func safeUpdateStaged(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && strings.HasPrefix(filepath.Base(path), ".paperboat-artifact-")
}

func syncUpdateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validReleaseVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func compareReleaseVersion(left, right string) int {
	l, r := strings.Split(left, "."), strings.Split(right, ".")
	for index := range 4 {
		var lv, rv uint64
		if index < len(l) {
			lv, _ = strconv.ParseUint(l[index], 10, 32)
		}
		if index < len(r) {
			rv, _ = strconv.ParseUint(r[index], 10, 32)
		}
		if lv < rv {
			return -1
		}
		if lv > rv {
			return 1
		}
	}
	return 0
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
)

const (
	lifecycleJournalVersion = "paperboat.service-lifecycle/v1"
	maxLifecycleJournalSize = 256 << 10
	maxLifecycleJournalAge  = 24 * time.Hour
	lifecycleClockSkew      = 5 * time.Minute
)

var (
	ErrLifecycleBusy      = errors.New("service lifecycle operation already in progress")
	ErrLifecycleInvalid   = errors.New("invalid service lifecycle configuration")
	ErrLifecycleNotReady  = errors.New("native service did not become ready")
	ErrLifecycleUncertain = errors.New("service lifecycle outcome is uncertain")
)

// NativeComponentStatus is the complete state which must survive a failed
// multi-component service operation. Definition contains the exact native
// declaration bytes and must never contain credentials.
type NativeComponentStatus struct {
	ID         string `json:"id"`
	Installed  bool   `json:"installed"`
	Enabled    bool   `json:"enabled"`
	Running    bool   `json:"running"`
	Ready      bool   `json:"ready"`
	Definition []byte `json:"definition,omitempty"`
}

// TransactionalComponent is the native service-manager boundary. Restore
// must reproduce the supplied status exactly enough that a retry or repair is
// deterministic: definition, enablement, running state, and readiness.
type TransactionalComponent interface {
	ID() string
	Inspect(context.Context) (NativeComponentStatus, error)
	Install(context.Context) error
	Start(context.Context) error
	Repair(context.Context) error
	Stop(context.Context) error
	Uninstall(context.Context) error
	Restore(context.Context, NativeComponentStatus) error
}

type LifecycleConfig struct {
	StateRoot       string
	Components      []TransactionalComponent
	Now             func() time.Time
	RollbackTimeout time.Duration
}

type LifecycleManager struct {
	stateRoot       string
	journal         string
	lockPath        string
	components      []TransactionalComponent
	now             func() time.Time
	rollbackTimeout time.Duration
}

type lifecycleOperation string

const (
	lifecycleInstall   lifecycleOperation = "install"
	lifecycleRepair    lifecycleOperation = "repair"
	lifecycleStop      lifecycleOperation = "stop"
	lifecycleUninstall lifecycleOperation = "uninstall"
)

type lifecycleJournal struct {
	Version   string                  `json:"version"`
	Operation lifecycleOperation      `json:"operation"`
	StartedAt time.Time               `json:"started_at"`
	Next      int                     `json:"next"`
	Order     []string                `json:"order"`
	Before    []NativeComponentStatus `json:"before"`
}

func NewLifecycleManager(config LifecycleConfig) (*LifecycleManager, error) {
	if !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot || len(config.Components) == 0 {
		return nil, ErrLifecycleInvalid
	}
	seen := make(map[string]struct{}, len(config.Components))
	components := make([]TransactionalComponent, len(config.Components))
	for index, component := range config.Components {
		if component == nil || !safeLifecycleID(component.ID()) {
			return nil, ErrLifecycleInvalid
		}
		if _, duplicate := seen[component.ID()]; duplicate {
			return nil, ErrLifecycleInvalid
		}
		seen[component.ID()] = struct{}{}
		components[index] = component
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	rollbackTimeout := config.RollbackTimeout
	if rollbackTimeout == 0 {
		rollbackTimeout = time.Minute
	}
	if rollbackTimeout < time.Second || rollbackTimeout > 5*time.Minute {
		return nil, ErrLifecycleInvalid
	}
	return &LifecycleManager{
		stateRoot:       config.StateRoot,
		journal:         filepath.Join(config.StateRoot, "service-lifecycle.json"),
		lockPath:        filepath.Join(config.StateRoot, "service-lifecycle.lock"),
		components:      components,
		now:             now,
		rollbackTimeout: rollbackTimeout,
	}, nil
}

func safeLifecycleID(value string) bool {
	if value == "" || len(value) > 64 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (m *LifecycleManager) Install(ctx context.Context) error {
	return m.execute(ctx, lifecycleInstall)
}

func (m *LifecycleManager) Repair(ctx context.Context) error {
	return m.execute(ctx, lifecycleRepair)
}

func (m *LifecycleManager) Stop(ctx context.Context) error {
	return m.execute(ctx, lifecycleStop)
}

func (m *LifecycleManager) Uninstall(ctx context.Context) error {
	return m.execute(ctx, lifecycleUninstall)
}

// Inspect returns a stable ID-sorted projection without mutating native state.
func (m *LifecycleManager) Inspect(ctx context.Context) ([]NativeComponentStatus, error) {
	if m == nil || ctx == nil {
		return nil, ErrLifecycleInvalid
	}
	result := make([]NativeComponentStatus, 0, len(m.components))
	for _, component := range m.components {
		status, err := component.Inspect(ctx)
		if err != nil {
			return nil, err
		}
		if status.ID != component.ID() || !validComponentStatus(status) {
			return nil, ErrLifecycleInvalid
		}
		status.Definition = append([]byte(nil), status.Definition...)
		result = append(result, status)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

// Recover rolls back a crash-interrupted operation to the exact pre-operation
// native states recorded before the first mutation. It is safe to call at
// every process start and is a no-op without a journal.
func (m *LifecycleManager) Recover(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrLifecycleInvalid
	}
	unlock, err := lockLifecycle(m.lockPath)
	if err != nil {
		return err
	}
	defer unlock()
	journal, err := m.readJournal()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrLifecycleUncertain, err)
	}
	if err := m.rollback(ctx, journal); err != nil {
		return errors.Join(ErrLifecycleUncertain, err)
	}
	return m.removeJournal()
}

func (m *LifecycleManager) execute(ctx context.Context, operation lifecycleOperation) error {
	if m == nil || ctx == nil || !validLifecycleOperation(operation) {
		return ErrLifecycleInvalid
	}
	unlock, err := lockLifecycle(m.lockPath)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Lstat(m.journal); err == nil {
		return ErrLifecycleUncertain
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	order := m.operationOrder(operation)
	journal := lifecycleJournal{
		Version: lifecycleJournalVersion, Operation: operation, StartedAt: m.now().UTC(),
		Order: make([]string, len(order)), Before: make([]NativeComponentStatus, len(order)),
	}
	for index, component := range order {
		status, inspectErr := component.Inspect(ctx)
		if inspectErr != nil {
			return inspectErr
		}
		if status.ID != component.ID() || !validComponentStatus(status) {
			return ErrLifecycleInvalid
		}
		status.Definition = append([]byte(nil), status.Definition...)
		journal.Order[index], journal.Before[index] = component.ID(), status
	}
	if err := m.writeJournal(journal); err != nil {
		return err
	}
	for index, component := range order {
		if err := applyLifecycleOperation(ctx, component, operation); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), m.rollbackTimeout)
			rollbackErr := m.rollback(rollbackCtx, journal)
			cancel()
			if rollbackErr == nil {
				rollbackErr = m.removeJournal()
			}
			return errors.Join(err, rollbackErr)
		}
		if err := verifyLifecycleOutcome(ctx, component, operation); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), m.rollbackTimeout)
			rollbackErr := m.rollback(rollbackCtx, journal)
			cancel()
			if rollbackErr == nil {
				rollbackErr = m.removeJournal()
			}
			return errors.Join(err, rollbackErr)
		}
		journal.Next = index + 1
		if err := m.writeJournal(journal); err != nil {
			return errors.Join(ErrLifecycleUncertain, err)
		}
	}
	return m.removeJournal()
}

func (m *LifecycleManager) operationOrder(operation lifecycleOperation) []TransactionalComponent {
	result := append([]TransactionalComponent(nil), m.components...)
	if operation == lifecycleStop || operation == lifecycleUninstall {
		for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
			result[left], result[right] = result[right], result[left]
		}
	}
	return result
}

func applyLifecycleOperation(ctx context.Context, component TransactionalComponent, operation lifecycleOperation) error {
	switch operation {
	case lifecycleInstall:
		if err := component.Install(ctx); err != nil {
			return err
		}
		return component.Start(ctx)
	case lifecycleRepair:
		if err := component.Repair(ctx); err != nil {
			return err
		}
		return component.Start(ctx)
	case lifecycleStop:
		return component.Stop(ctx)
	case lifecycleUninstall:
		if err := component.Stop(ctx); err != nil {
			return err
		}
		return component.Uninstall(ctx)
	default:
		return ErrLifecycleInvalid
	}
}

func verifyLifecycleOutcome(ctx context.Context, component TransactionalComponent, operation lifecycleOperation) error {
	status, err := component.Inspect(ctx)
	if err != nil {
		return err
	}
	if status.ID != component.ID() || !validComponentStatus(status) {
		return ErrLifecycleInvalid
	}
	switch operation {
	case lifecycleInstall, lifecycleRepair:
		if !status.Installed || !status.Enabled || !status.Running || !status.Ready {
			return fmt.Errorf("%w: %s", ErrLifecycleNotReady, component.ID())
		}
		if checker, ok := component.(interface{ CheckReadiness(context.Context) error }); ok {
			if probeErr := checker.CheckReadiness(ctx); probeErr != nil {
				return errors.Join(fmt.Errorf("%w: %s", ErrLifecycleNotReady, component.ID()), probeErr)
			}
		}
	case lifecycleStop:
		if status.Running || status.Ready {
			return fmt.Errorf("%w: %s did not stop", ErrLifecycleNotReady, component.ID())
		}
	case lifecycleUninstall:
		if status.Installed || status.Enabled || status.Running || status.Ready || len(status.Definition) != 0 {
			return fmt.Errorf("%w: %s remains installed", ErrLifecycleNotReady, component.ID())
		}
	}
	return nil
}

func validComponentStatus(status NativeComponentStatus) bool {
	if !safeLifecycleID(status.ID) || len(status.Definition) > maxLifecycleJournalSize/2 {
		return false
	}
	if !status.Installed {
		return !status.Enabled && !status.Running && !status.Ready && len(status.Definition) == 0
	}
	if status.Ready && !status.Running || status.Running && !status.Enabled {
		return false
	}
	return len(status.Definition) > 0
}

func validLifecycleOperation(operation lifecycleOperation) bool {
	switch operation {
	case lifecycleInstall, lifecycleRepair, lifecycleStop, lifecycleUninstall:
		return true
	default:
		return false
	}
}

func (m *LifecycleManager) rollback(ctx context.Context, journal lifecycleJournal) error {
	components := make(map[string]TransactionalComponent, len(m.components))
	for _, component := range m.components {
		components[component.ID()] = component
	}
	var joined error
	for index := len(journal.Order) - 1; index >= 0; index-- {
		component := components[journal.Order[index]]
		if component == nil {
			joined = errors.Join(joined, ErrLifecycleInvalid)
			continue
		}
		before := journal.Before[index]
		before.Definition = append([]byte(nil), before.Definition...)
		if err := component.Restore(ctx, before); err != nil {
			joined = errors.Join(joined, fmt.Errorf("restore %s: %w", component.ID(), err))
			continue
		}
		after, err := component.Inspect(ctx)
		if err != nil || !sameComponentStatus(before, after) {
			joined = errors.Join(joined, fmt.Errorf("restore %s: %w", component.ID(), ErrLifecycleUncertain), err)
		}
	}
	return joined
}

func sameComponentStatus(left, right NativeComponentStatus) bool {
	return left.ID == right.ID && left.Installed == right.Installed && left.Enabled == right.Enabled &&
		left.Running == right.Running && left.Ready == right.Ready && bytes.Equal(left.Definition, right.Definition)
}

func (m *LifecycleManager) writeJournal(journal lifecycleJournal) error {
	if err := os.MkdirAll(m.stateRoot, 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded) > maxLifecycleJournalSize {
		return errors.Join(ErrLifecycleInvalid, err)
	}
	return atomicfile.Write(m.journal, encoded, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func (m *LifecycleManager) readJournal() (lifecycleJournal, error) {
	file, err := os.Open(m.journal)
	if err != nil {
		return lifecycleJournal{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxLifecycleJournalSize+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxLifecycleJournalSize {
		return lifecycleJournal{}, errors.Join(ErrLifecycleInvalid, err)
	}
	if _, err := operation.CanonicalHash(encoded); err != nil {
		return lifecycleJournal{}, errors.Join(ErrLifecycleInvalid, err)
	}
	if err := rejectDuplicateJSONFields(encoded); err != nil {
		return lifecycleJournal{}, errors.Join(ErrLifecycleInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var journal lifecycleJournal
	if err := decoder.Decode(&journal); err != nil {
		return lifecycleJournal{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return lifecycleJournal{}, ErrLifecycleInvalid
	}
	now := m.now().UTC()
	if journal.Version != lifecycleJournalVersion || !validLifecycleOperation(journal.Operation) || journal.StartedAt.IsZero() || journal.StartedAt.After(now.Add(lifecycleClockSkew)) || now.Sub(journal.StartedAt) > maxLifecycleJournalAge || len(journal.Order) != len(m.components) || len(journal.Before) != len(journal.Order) || journal.Next < 0 || journal.Next > len(journal.Order) {
		return lifecycleJournal{}, ErrLifecycleInvalid
	}
	seen := make(map[string]struct{}, len(journal.Order))
	for index, id := range journal.Order {
		if !safeLifecycleID(id) || journal.Before[index].ID != id || !validComponentStatus(journal.Before[index]) {
			return lifecycleJournal{}, ErrLifecycleInvalid
		}
		if _, duplicate := seen[id]; duplicate {
			return lifecycleJournal{}, ErrLifecycleInvalid
		}
		seen[id] = struct{}{}
	}
	return journal, nil
}

func (m *LifecycleManager) removeJournal() error {
	err := os.Remove(m.journal)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncServiceDirectory(m.stateRoot)
}

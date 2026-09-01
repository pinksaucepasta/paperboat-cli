//go:build darwin || linux

package runtime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
)

type runtimeTestGenesisMarker struct {
	mu   sync.Mutex
	path string
}

type runtimeTestGenesisRecord struct {
	State environmentkey.GenesisState `json:"state"`
}

func runtimeTestGenesisMarkerFor(t *testing.T, path string) environmentkey.GenesisMarker {
	t.Helper()
	marker := &runtimeTestGenesisMarker{path: path + ".paperboat-secure-genesis"}
	if _, err := os.Lstat(marker.path); errors.Is(err, os.ErrNotExist) {
		if err := marker.writeLocked(environmentkey.GenesisFresh); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	return marker
}

func (m *runtimeTestGenesisMarker) GenesisState() (environmentkey.GenesisState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readLocked()
}

func (m *runtimeTestGenesisMarker) PrepareGenesis() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.readLocked()
	if err != nil {
		return err
	}
	switch state {
	case environmentkey.GenesisFresh:
		return m.writeLocked(environmentkey.GenesisPending)
	case environmentkey.GenesisPending:
		return nil
	case environmentkey.GenesisEstablished:
		return environmentkey.ErrGenesisAlreadyEstablished
	default:
		return environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *runtimeTestGenesisMarker) CommitGenesis() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.readLocked()
	if err != nil {
		return err
	}
	switch state {
	case environmentkey.GenesisPending:
		return m.writeLocked(environmentkey.GenesisEstablished)
	case environmentkey.GenesisEstablished:
		return nil
	case environmentkey.GenesisFresh:
		return environmentkey.ErrGenesisNotPrepared
	default:
		return environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *runtimeTestGenesisMarker) readLocked() (environmentkey.GenesisState, error) {
	body, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", environmentkey.ErrGenesisMarkerMissing
		}
		return "", err
	}
	var record runtimeTestGenesisRecord
	if json.Unmarshal(body, &record) != nil {
		return "", environmentkey.ErrGenesisMarkerInvalid
	}
	switch record.State {
	case environmentkey.GenesisFresh, environmentkey.GenesisPending, environmentkey.GenesisEstablished:
		return record.State, nil
	default:
		return "", environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *runtimeTestGenesisMarker) writeLocked(state environmentkey.GenesisState) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(runtimeTestGenesisRecord{State: state})
	if err != nil {
		return err
	}
	return atomicfile.Write(m.path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

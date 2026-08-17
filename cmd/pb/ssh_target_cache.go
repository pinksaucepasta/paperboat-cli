package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/userpaths"
)

const (
	sshTargetCacheVersion = 1
	sshTargetCacheFile    = "ssh-targets.json"
	// sshTargetCacheTTL bounds how long a cached SSH target (port and OS user)
	// may be used without a live fetch. The managed SSH proxy revalidates the
	// destination port against fresh server data on every connection, so a
	// stale cache entry can only produce a clear validation error, never a
	// wrong connection.
	sshTargetCacheTTL = 5 * time.Minute
)

type sshTargetCacheEntry struct {
	Version           int    `json:"version"`
	ServerURL         string `json:"server_url"`
	Alias             string `json:"alias"`
	MachineID         string `json:"machine_id"`
	MachineGeneration uint64 `json:"machine_generation"`
	OSUser            string `json:"os_user"`
	Port              uint16 `json:"port"`
	FetchedAtUnix     int64  `json:"fetched_at_unix"`
}

type sshTargetCache struct {
	Version int                            `json:"version"`
	Entries map[string]sshTargetCacheEntry `json:"entries"`
}

func sshTargetCacheFilePath() (string, error) {
	dir, err := userpaths.Config("paperboat")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sshTargetCacheFile), nil
}

func loadSSHTargetCache(serverURL, alias string, now time.Time) (sshTargetCacheEntry, bool) {
	path, err := sshTargetCacheFilePath()
	if err != nil {
		return sshTargetCacheEntry{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sshTargetCacheEntry{}, false
	}
	var cache sshTargetCache
	if json.Unmarshal(data, &cache) != nil || cache.Version != sshTargetCacheVersion {
		return sshTargetCacheEntry{}, false
	}
	entry, ok := cache.Entries[alias]
	if !ok || entry.Version != sshTargetCacheVersion || entry.ServerURL != serverURL || entry.Alias != alias || entry.OSUser == "" || entry.Port == 0 || entry.MachineID == "" || entry.MachineGeneration == 0 {
		return sshTargetCacheEntry{}, false
	}
	fetchedAt := time.Unix(entry.FetchedAtUnix, 0)
	if fetchedAt.After(now) || now.Sub(fetchedAt) > sshTargetCacheTTL {
		return sshTargetCacheEntry{}, false
	}
	return entry, true
}

func storeSSHTargetCache(serverURL, alias string, target api.ManagedSSHTarget, machineID string, machineGeneration uint64, now time.Time) error {
	if target.OSUser == "" || target.Port == 0 || alias == "" || machineID == "" || machineGeneration == 0 {
		return errors.New("incomplete SSH target cache entry")
	}
	entry := sshTargetCacheEntry{
		Version:           sshTargetCacheVersion,
		ServerURL:         serverURL,
		Alias:             alias,
		MachineID:         machineID,
		MachineGeneration: machineGeneration,
		OSUser:            target.OSUser,
		Port:              target.Port,
		FetchedAtUnix:     now.Unix(),
	}
	path, err := sshTargetCacheFilePath()
	if err != nil {
		return err
	}
	cache := sshTargetCache{Version: sshTargetCacheVersion, Entries: map[string]sshTargetCacheEntry{}}
	if data, readErr := os.ReadFile(path); readErr == nil {
		if json.Unmarshal(data, &cache) == nil && cache.Version == sshTargetCacheVersion && cache.Entries != nil {
			for key, existing := range cache.Entries {
				if existing.FetchedAtUnix < now.Unix()-int64((24*time.Hour)/time.Second) {
					delete(cache.Entries, key)
				}
			}
		} else {
			cache.Entries = map[string]sshTargetCacheEntry{}
		}
	}
	cache.Entries[alias] = entry
	encoded, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(encoded, '\n'), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func sshTargetCacheLookup(cfg *config.Config, machine api.UserMachine, now time.Time) (api.ManagedSSHTarget, bool) {
	if cfg == nil || cfg.ServerURL == "" || machine.Alias == "" || machine.ID == "" || machine.InstallationGeneration < 1 {
		return api.ManagedSSHTarget{}, false
	}
	entry, ok := loadSSHTargetCache(cfg.ServerURL, machine.Alias, now)
	if !ok || entry.MachineID != machine.ID || entry.MachineGeneration != uint64(machine.InstallationGeneration) {
		return api.ManagedSSHTarget{}, false
	}
	return api.ManagedSSHTarget{Type: "ssh_target", Version: 1, MachineID: entry.MachineID, MachineGeneration: entry.MachineGeneration, OSUser: entry.OSUser, Port: entry.Port}, true
}

func sshTargetCacheStore(cfg *config.Config, machine api.UserMachine, target api.ManagedSSHTarget, now time.Time) error {
	if cfg == nil || cfg.ServerURL == "" || machine.Alias == "" || machine.ID == "" || machine.InstallationGeneration < 1 {
		return errors.New("cannot store SSH target without resolved machine identity")
	}
	return storeSSHTargetCache(cfg.ServerURL, machine.Alias, target, machine.ID, uint64(machine.InstallationGeneration), now)
}

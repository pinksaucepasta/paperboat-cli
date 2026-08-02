package fileindex

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const cacheVersion = 1

var activeRefreshes sync.Map

type refreshCall struct {
	done  chan struct{}
	files []string
	err   error
}

type directory struct {
	ModTime  int64    `json:"mod_time"`
	Files    []string `json:"files,omitempty"`
	Children []string `json:"children,omitempty"`
}

type cache struct {
	Version     int                  `json:"version"`
	Root        string               `json:"root"`
	Directories map[string]directory `json:"directories"`
}

func CachePath() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "paperboat", "file-index.json"), nil
}

func Load(root, cachePath string) ([]string, bool) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, false
	}
	value, ok := loadCache(cachePath, absoluteRoot)
	if !ok {
		return nil, false
	}
	files := make([]string, 0, 4096)
	for _, record := range value.Directories {
		files = append(files, record.Files...)
	}
	sort.Strings(files)
	return files, true
}

func RefreshInBackground(root, cachePath string) {
	_ = startRefresh(root, cachePath)
}

func RefreshReady(cachePath string) bool {
	value, ok := activeRefreshes.Load(cachePath)
	if !ok {
		return false
	}
	select {
	case <-value.(*refreshCall).done:
		return true
	default:
		return false
	}
}

// Current waits for the refresh started by the home screen, or starts one
// when this process has not warmed the index yet.
func Current(ctx context.Context, root, cachePath string) ([]string, error) {
	call := startRefresh(root, cachePath)
	select {
	case <-call.done:
		activeRefreshes.CompareAndDelete(cachePath, call)
		return call.files, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func startRefresh(root, cachePath string) *refreshCall {
	call := &refreshCall{done: make(chan struct{})}
	actual, loaded := activeRefreshes.LoadOrStore(cachePath, call)
	if loaded {
		return actual.(*refreshCall)
	}
	go func() {
		defer close(call.done)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		call.files, call.err = Refresh(ctx, root, cachePath)
	}()
	return call
}

// Refresh returns regular, non-hidden files and persists directory metadata so
// later refreshes only reread directories whose immediate contents changed.
func Refresh(ctx context.Context, root, cachePath string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	previous := readCache(cachePath, root)
	next := cache{Version: cacheVersion, Root: root, Directories: make(map[string]directory, len(previous.Directories))}
	queue := []string{root}
	files := make([]string, 0, 4096)
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dir := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		info, statErr := os.Stat(dir)
		if statErr != nil || !info.IsDir() {
			continue
		}
		record, unchanged := previous.Directories[dir]
		if !unchanged || record.ModTime != info.ModTime().UnixNano() {
			var readOK bool
			record, readOK = readDirectory(root, dir, info.ModTime().UnixNano())
			if !readOK {
				continue
			}
		}
		next.Directories[dir] = record
		files = append(files, record.Files...)
		queue = append(queue, record.Children...)
	}
	sort.Strings(files)
	if err := writeCache(cachePath, next); err != nil {
		return nil, err
	}
	return files, nil
}

func readDirectory(root, dir string, modTime int64) (directory, bool) {
	record := directory{ModTime: modTime}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return record, false
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || (entry.IsDir() && skipDirectory(runtime.GOOS, root, dir, name)) {
			continue
		}
		path := filepath.Join(dir, name)
		if entry.IsDir() {
			record.Children = append(record.Children, path)
			continue
		}
		info, infoErr := entry.Info()
		if infoErr == nil && info.Mode().IsRegular() {
			record.Files = append(record.Files, path)
		}
	}
	return record, true
}

func skipDirectory(goos, root, parent, name string) bool {
	if name == "node_modules" || name == "vendor" {
		return true
	}
	if goos != "darwin" {
		return false
	}
	return parent == root && name == "Library" || strings.HasSuffix(strings.ToLower(name), ".app")
}

func readCache(path, root string) cache {
	value, ok := loadCache(path, root)
	if !ok {
		return cache{Version: cacheVersion, Root: root, Directories: map[string]directory{}}
	}
	return value
}

func loadCache(path, root string) (cache, bool) {
	value := cache{Version: cacheVersion, Root: root, Directories: map[string]directory{}}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &value) != nil || value.Version != cacheVersion || value.Root != root || value.Directories == nil {
		return cache{}, false
	}
	return value, true
}

func writeCache(path string, value cache) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".file-index-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if chmodErr := temporary.Chmod(0o600); chmodErr != nil {
		temporary.Close()
		return chmodErr
	}
	if _, err = temporary.Write(data); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

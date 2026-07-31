package inbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/filetransfer"
)

const (
	journalName       = ".paperboat-receipts.json"
	maxJournalEntries = 1024
)

type Client interface {
	Pending(context.Context, string, int) ([]filetransfer.Manifest, error)
	Content(context.Context, filetransfer.Manifest, int64) (*http.Response, error)
	Receipt(context.Context, string, string, string) error
}

type Config struct {
	Client      Client
	MachineID   string
	SessionID   string
	Path        string
	Notify      func(string)
	PollSeconds int
}

type Inbox struct {
	config Config
	mu     sync.Mutex
}

type receipt struct {
	Digest string    `json:"digest"`
	Path   string    `json:"path"`
	At     time.Time `json:"at"`
}

type journal struct {
	Version int                `json:"version"`
	Entries map[string]receipt `json:"entries"`
}

func New(config Config) (*Inbox, error) {
	if config.Client == nil || config.MachineID == "" || config.SessionID == "" {
		return nil, errors.New("invalid inbox configuration")
	}
	if err := EnsurePath(config.Path); err != nil {
		return nil, err
	}
	if config.PollSeconds == 0 {
		config.PollSeconds = 30
	}
	if config.PollSeconds < 1 || config.PollSeconds > 30 {
		return nil, errors.New("invalid inbox poll duration")
	}
	return &Inbox{config: config}, nil
}

func (i *Inbox) Run(ctx context.Context) error {
	for {
		transfers, err := i.config.Client.Pending(ctx, i.config.SessionID, i.config.PollSeconds)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		for _, transfer := range transfers {
			path, deliveryErr := i.Deliver(ctx, transfer)
			if deliveryErr != nil {
				code := errorCode(deliveryErr)
				_ = i.config.Client.Receipt(ctx, transfer.TransferID, code, "")
				continue
			}
			if err := i.config.Client.Receipt(ctx, transfer.TransferID, "stored", path); err != nil {
				continue
			}
			if i.config.Notify != nil {
				i.config.Notify("Saved to " + path)
			}
		}
	}
}

func (i *Inbox) Deliver(ctx context.Context, manifest filetransfer.Manifest) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.validateManifest(manifest); err != nil {
		return "", err
	}
	root := i.config.Path
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", storageError(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", storageError(err)
	}
	receipts, err := loadJournal(root)
	if err != nil {
		return "", storageError(err)
	}
	prior, hasPrior := receipts.Entries[manifest.TransferID]
	if hasPrior {
		if prior.Digest != manifest.SHA256 {
			return "", errors.New("digest_mismatch")
		}
		name := strings.TrimPrefix(filepath.ToSlash(prior.Path), "Paperboat Inbox/")
		if name == prior.Path || filepath.Base(name) != name {
			return "", storageError(errors.New("receipt journal is corrupt"))
		}
		finalPath := filepath.Join(root, filepath.FromSlash(name))
		if info, statErr := os.Lstat(finalPath); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			if info.Size() != manifest.Size {
				return "", errors.New("digest_mismatch")
			}
			matches, verifyErr := fileDigestMatches(finalPath, manifest.SHA256)
			if verifyErr != nil {
				return "", storageError(verifyErr)
			}
			if !matches {
				return "", errors.New("digest_mismatch")
			}
			return prior.Path, nil
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", storageError(statErr)
		}
	}

	tempPath := filepath.Join(root, ".paperboat-transfer-"+manifest.TransferID+".part")
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", storageError(err)
	}
	keepTemp := true
	defer func() {
		_ = file.Close()
		if !keepTemp {
			_ = os.Remove(tempPath)
		}
	}()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > manifest.Size {
		_ = file.Truncate(0)
		return "", errors.New("invalid_size")
	}
	offset := info.Size()
	hash := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", storageError(err)
	}
	if copied, err := io.CopyN(hash, file, offset); err != nil || copied != offset {
		return "", storageError(errors.Join(err, io.ErrUnexpectedEOF))
	}
	if offset < manifest.Size {
		response, err := i.config.Client.Content(ctx, manifest, offset)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		if offset > 0 && response.StatusCode != http.StatusPartialContent || offset == 0 && response.StatusCode != http.StatusOK {
			return "", errors.New("offset_conflict")
		}
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return "", storageError(err)
		}
		remaining := manifest.Size - offset
		written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, remaining+1))
		if copyErr != nil {
			return "", copyErr
		}
		if written != remaining {
			return "", errors.New("invalid_size")
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		keepTemp = false
		return "", errors.New("digest_mismatch")
	}
	if err := file.Sync(); err != nil {
		return "", storageError(err)
	}
	if err := file.Close(); err != nil {
		return "", storageError(err)
	}

	var finalName, relativePath string
	if hasPrior {
		relativePath = prior.Path
		finalName = strings.TrimPrefix(filepath.ToSlash(prior.Path), "Paperboat Inbox/")
	} else {
		finalName, err = availableName(root, localBasename(manifest.Basename, runtime.GOOS))
		if err != nil {
			return "", storageError(err)
		}
		relativePath = filepath.ToSlash(filepath.Join("Paperboat Inbox", finalName))
		receipts.Entries[manifest.TransferID] = receipt{Digest: manifest.SHA256, Path: relativePath, At: time.Now().UTC()}
		boundJournal(&receipts)
		if err := saveJournal(root, receipts); err != nil {
			return "", storageError(err)
		}
	}
	if err := os.Link(tempPath, filepath.Join(root, filepath.FromSlash(finalName))); err != nil {
		return "", storageError(err)
	}
	if err := syncDir(root); err != nil {
		return "", storageError(err)
	}
	keepTemp = false
	if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", storageError(err)
	}
	if err := syncDir(root); err != nil {
		return "", storageError(err)
	}
	return relativePath, nil
}

func DefaultPath() (string, error) {
	downloads, err := DownloadsDir()
	if err == nil && filepath.IsAbs(downloads) {
		return filepath.Join(downloads, "Paperboat Inbox"), nil
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return "", errors.Join(err, homeErr)
	}
	return filepath.Join(home, "Documents", "Paperboat Inbox"), nil
}

func EnsurePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("inbox path must be an absolute clean path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return ValidatePath(path)
}

func ValidatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("inbox path must be an absolute clean path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("inbox path must be an existing non-symlink directory")
	}
	if !ownedByCurrentUser(info) {
		return errors.New("inbox path must be owned by the current user")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("inbox path must not be writable by group or other users")
	}
	probe, err := os.CreateTemp(path, ".paperboat-inbox-probe-*")
	if err != nil {
		return errors.New("inbox path is not writable")
	}
	probePath := probe.Name()
	if closeErr := probe.Close(); closeErr != nil {
		_ = os.Remove(probePath)
		return closeErr
	}
	if err := os.Remove(probePath); err != nil {
		return err
	}
	return nil
}

func fileDigestMatches(path, expected string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}
	return hex.EncodeToString(hash.Sum(nil)) == expected, nil
}

func (i *Inbox) validateManifest(manifest filetransfer.Manifest) error {
	if manifest.TransferID == "" || manifest.DestinationMachineID != i.config.MachineID || manifest.Size < 0 || manifest.Size > 50<<20 || len(manifest.SHA256) != 64 {
		return errors.New("invalid_size")
	}
	if _, err := hex.DecodeString(manifest.SHA256); err != nil || manifest.SHA256 != strings.ToLower(manifest.SHA256) {
		return errors.New("digest_mismatch")
	}
	name := manifest.Basename
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("invalid_path")
	}
	return nil
}

func localBasename(name, goos string) string {
	if goos != "windows" {
		return name
	}
	name = strings.Map(func(value rune) rune {
		if value < 32 || strings.ContainsRune(`<>:"/\|?*`, value) {
			return '_'
		}
		return value
	}, name)
	name = strings.TrimRight(name, ". ")
	if name == "" {
		name = "_"
	}
	stem := strings.ToUpper(strings.TrimSuffix(name, filepath.Ext(name)))
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
		name = "_" + name
	}
	return name
}

func availableName(root, basename string) (string, error) {
	extension := filepath.Ext(basename)
	stem := strings.TrimSuffix(basename, extension)
	for index := 1; index <= 10000; index++ {
		name := basename
		if index > 1 {
			name = fmt.Sprintf("%s (%d)%s", stem, index, extension)
		}
		_, err := os.Lstat(filepath.Join(root, name))
		if errors.Is(err, os.ErrNotExist) {
			return name, nil
		}
		if err == nil {
			continue
		}
		return "", err
	}
	return "", errors.New("resource_limit")
}

func loadJournal(root string) (journal, error) {
	result := journal{Version: 1, Entries: make(map[string]receipt)}
	data, err := os.ReadFile(filepath.Join(root, journalName))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.Version != 1 || result.Entries == nil {
		return journal{}, errors.New("receipt journal is corrupt")
	}
	return result, nil
}

func saveJournal(root string, value journal) error {
	tempPath := filepath.Join(root, journalName+".tmp")
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(root, journalName)); err != nil {
		return err
	}
	return syncDir(root)
}

func boundJournal(value *journal) {
	for len(value.Entries) > maxJournalEntries {
		var oldestID string
		var oldest time.Time
		for id, entry := range value.Entries {
			if oldestID == "" || entry.At.Before(oldest) || entry.At.Equal(oldest) && id < oldestID {
				oldestID, oldest = id, entry.At
			}
		}
		delete(value.Entries, oldestID)
	}
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func storageError(err error) error { return fmt.Errorf("storage_unavailable: %w", err) }

func errorCode(err error) string {
	for _, code := range []string{"invalid_path", "invalid_size", "digest_mismatch", "offset_conflict", "resource_limit", "canceled"} {
		if strings.Contains(err.Error(), code) {
			return code
		}
	}
	return "storage_unavailable"
}

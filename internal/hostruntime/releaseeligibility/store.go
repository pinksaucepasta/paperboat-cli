// Package releaseeligibility owns the small, durable local records that affect
// release selection. Signed rollout state stays in TUF release metadata;
// this package only stores an operator-approved, bounded deferral.
package releaseeligibility

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

const MaxDeferralBytes int64 = 64 << 10

var (
	ErrInvalidStore   = errors.New("invalid release eligibility store")
	ErrUnsafePath     = errors.New("unsafe release eligibility path")
	ErrInvalidRecord  = errors.New("invalid release eligibility record")
	ErrRecordTooLarge = errors.New("release eligibility record is too large")
	ErrRecordChanged  = errors.New("release eligibility record changed while reading")
	ErrDirectorySync  = errors.New("release eligibility directory sync failed")
)

// FileStore is a strict, single-record store. The path is supplied by the
// host configuration, never by a release index or a network response.
type FileStore struct {
	Path     string
	MaxBytes int64
}

func NewFileStore(path string) (FileStore, error) {
	store := FileStore{Path: path, MaxBytes: MaxDeferralBytes}
	if err := store.validate(); err != nil {
		return FileStore{}, err
	}
	return store, nil
}

func (s FileStore) validate() error {
	if !validAbsolutePath(s.Path) || s.MaxBytes <= 0 || s.MaxBytes > MaxDeferralBytes {
		return ErrInvalidStore
	}
	return nil
}

// CurrentDeferral implements workerupdate.DeferralSource structurally without
// importing workerupdate (which keeps the package dependency acyclic).
func (s FileStore) CurrentDeferral(ctx context.Context) (releasepolicy.Deferral, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.validate(); err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	if err := validateParentDirectory(s.Path); err != nil {
		return releasepolicy.Deferral{}, false, err
	}

	before, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return releasepolicy.Deferral{}, false, nil
	}
	if err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	if err := validateRecordInfo(s.Path, before); err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameFile(before, opened) {
		return releasepolicy.Deferral{}, false, ErrRecordChanged
	}
	body, err := readBounded(ctx, file, s.MaxBytes)
	if err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	after, err := file.Stat()
	if err != nil || !sameFile(opened, after) {
		return releasepolicy.Deferral{}, false, ErrRecordChanged
	}
	if err := ctx.Err(); err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	deferral, err := decode(body)
	if err != nil {
		return releasepolicy.Deferral{}, false, err
	}
	return deferral, true, nil
}

// Save atomically replaces the single record and fsyncs both the file and its
// containing directory. The temporary file is created with 0600 permissions
// in the same directory, so a process crash cannot expose a partial record.
func (s FileStore) Save(ctx context.Context, deferral releasepolicy.Deferral) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := deferral.Bytes()
	if err != nil || int64(len(body)) > s.MaxBytes {
		if err != nil {
			return errors.Join(ErrInvalidRecord, err)
		}
		return ErrRecordTooLarge
	}
	if err := validateParentDirectory(s.Path); err != nil {
		return err
	}
	if info, statErr := os.Lstat(s.Path); statErr == nil {
		if err := validateRecordInfo(s.Path, info); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	temporary, temporaryPath, err := createTemporaryFile(filepath.Dir(s.Path), filepath.Base(s.Path))
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	// On Windows, Chmod does not establish ownership or a protected DACL.
	// Apply the platform security policy before any bytes are written so an
	// attacker cannot observe or replace an unprotected staging record.
	if err := secureRecordFile(temporaryPath); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := writeBounded(ctx, temporary, body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=release-eligibility reason=same-directory-synced-protected-state-staging
	if err := os.Rename(temporaryPath, s.Path); err != nil {
		return err
	}
	removeTemporary = false
	// Rename preserves the protected temporary object's security on Windows,
	// but verify the final name as well. This also catches a hostile rename
	// target race before the directory durability barrier is reported.
	if err := secureRecordFile(s.Path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(s.Path)); err != nil {
		return errors.Join(ErrDirectorySync, err)
	}
	return nil
}

// Remove deletes this store's exact configured record. Missing records are
// already in the desired state. It is intentionally not recursive.
func (s FileStore) Remove(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateParentDirectory(s.Path); err != nil {
		return err
	}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateRecordInfo(s.Path, info); err != nil {
		return err
	}
	if err := os.Remove(s.Path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(s.Path))
}

func decode(body []byte) (releasepolicy.Deferral, error) {
	if err := rejectDuplicateKeys(body); err != nil {
		return releasepolicy.Deferral{}, ErrInvalidRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var deferral releasepolicy.Deferral
	var extra any
	if decoder.Decode(&deferral) != nil || decoder.Decode(&extra) != io.EOF || deferral.Validate() != nil {
		return releasepolicy.Deferral{}, ErrInvalidRecord
	}
	return deferral, nil
}

func rejectDuplicateKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalidRecord
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return ErrInvalidRecord
				}
				if _, duplicate := seen[name]; duplicate {
					return ErrInvalidRecord
				}
				seen[name] = struct{}{}
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalidRecord
			}
		case '[':
			for decoder.More() {
				if err := consumeJSONValue(decoder); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalidRecord
			}
		default:
			return ErrInvalidRecord
		}
	}
	return nil
}

func readBounded(ctx context.Context, reader io.Reader, maximum int64) ([]byte, error) {
	if maximum <= 0 || maximum > MaxDeferralBytes {
		return nil, ErrInvalidStore
	}
	buffer := make([]byte, 0, minInt64(maximum, 4096))
	chunk := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		read, err := reader.Read(chunk)
		if read > 0 {
			if int64(len(buffer))+int64(read) > maximum {
				return nil, ErrRecordTooLarge
			}
			buffer = append(buffer, chunk[:read]...)
		}
		if err == io.EOF {
			return buffer, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func writeBounded(ctx context.Context, writer io.Writer, body []byte) error {
	for len(body) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := writer.Write(body)
		if written > 0 {
			body = body[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != "." && filepath.Dir(path) != path && !containsControl(path)
}

func containsControl(value string) bool {
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return true
		}
	}
	return false
}

func validateParentDirectory(path string) error {
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrUnsafePath
	}
	return validateParentSecurity(directory, info)
}

func validateRecordInfo(path string, info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 {
		return ErrUnsafePath
	}
	if info.Size() > MaxDeferralBytes {
		return ErrRecordTooLarge
	}
	return validateRecordSecurity(path, info)
}

func sameFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime()) && left.Mode().Perm() == right.Mode().Perm()
}

func minInt64(value, maximum int64) int {
	if value < maximum {
		return int(value)
	}
	return int(maximum)
}

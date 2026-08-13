package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
)

type Stage string

const (
	StageValidate Stage = "validate"
	StageCreate   Stage = "create"
	StageWrite    Stage = "write"
	StageOwner    Stage = "owner"
	StageReplace  Stage = "replace"
	StageSyncDir  Stage = "sync_parent"
)

type Error struct {
	Stage Stage
	Path  string
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("atomic file %s %s: %v", e.Stage, e.Path, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

type Options struct {
	Mode     fs.FileMode
	OwnerUID int
	OwnerGID int
}

func Write(path string, data []byte, options Options) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || options.Mode.Perm() == 0 || options.Mode&^fs.ModePerm != 0 || options.OwnerUID < -1 || options.OwnerGID < -1 {
		return &Error{Stage: StageValidate, Path: path, Err: errors.New("invalid path, mode, or owner")}
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("parent is not a real directory")
		}
		return &Error{Stage: StageValidate, Path: path, Err: err}
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Stage: StageValidate, Path: path, Err: errors.New("destination is not a regular file")}
		}
		if options.OwnerUID >= 0 && fileOwnerUID(info) != options.OwnerUID {
			return &Error{Stage: StageValidate, Path: path, Err: errors.New("destination owner mismatch")}
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return &Error{Stage: StageValidate, Path: path, Err: statErr}
	}

	pending, err := renameio.NewPendingFile(path,
		renameio.WithTempDir(parent),
		renameio.WithStaticPermissions(options.Mode.Perm()),
	)
	if err != nil {
		return &Error{Stage: StageCreate, Path: path, Err: err}
	}
	defer pending.Cleanup()
	if _, err := pending.Write(data); err != nil {
		return &Error{Stage: StageWrite, Path: path, Err: err}
	}
	if options.OwnerUID >= 0 || options.OwnerGID >= 0 {
		if err := pending.Chown(options.OwnerUID, options.OwnerGID); err != nil {
			return &Error{Stage: StageOwner, Path: path, Err: err}
		}
	}
	if err := pending.CloseAtomicallyReplace(); err != nil {
		return &Error{Stage: StageReplace, Path: path, Err: err}
	}
	directory, err := os.Open(parent)
	if err != nil {
		return &Error{Stage: StageSyncDir, Path: path, Err: err}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return &Error{Stage: StageSyncDir, Path: path, Err: err}
	}
	return nil
}

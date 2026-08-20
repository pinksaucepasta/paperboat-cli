//go:build darwin || linux

package diagnostics

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

func resolveDiagnosticOwner(config DiskConfig) (diagnosticOwner, error) {
	if config.OwnerUID < 0 {
		return diagnosticOwner{}, ErrInvalid
	}
	return diagnosticOwner{uid: config.OwnerUID}, nil
}

func ensureDiagnosticDirectory(path string, owner diagnosticOwner) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || fileUID(info) != owner.uid {
		return ErrInvalid
	}
	return nil
}

func verifiedDiagnosticFile(path string, owner diagnosticOwner) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !validDiagnosticFile(path, info, owner) {
		return nil, ErrInvalid
	}
	return info, nil
}

func validDiagnosticFile(_ string, info os.FileInfo, owner diagnosticOwner) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && fileUID(info) == owner.uid
}

func createDiagnosticSegment(path string, owner diagnosticOwner) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

func openDiagnosticAppend(path string, owner diagnosticOwner) (*os.File, error) {
	before, err := verifiedDiagnosticFile(path, owner)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !validDiagnosticFile(path, info, owner) || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func openDiagnosticRead(path string, owner diagnosticOwner) (*os.File, error) {
	before, err := verifiedDiagnosticFile(path, owner)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !validDiagnosticFile(path, info, owner) || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func removeDiagnosticFile(path string, owner diagnosticOwner) error {
	if _, err := verifiedDiagnosticFile(path, owner); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeDiagnosticAtomic(path string, value []byte, owner diagnosticOwner) error {
	if err := atomicfile.Write(path, value, atomicfile.Options{Mode: 0o600, OwnerUID: owner.uid, OwnerGID: -1}); err != nil {
		return err
	}
	_, err := verifiedDiagnosticFile(path, owner)
	return err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func fileUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

//go:build windows

package managedssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

type pinnedWindowsSSHFile struct {
	file   *os.File
	handle windows.Handle
	value  []byte
}

func (f *pinnedWindowsSSHFile) Close() error {
	if f == nil || f.file == nil {
		return nil
	}
	return f.file.Close()
}

// openPinnedWindowsSSHFile opens one ordinary file without delete sharing,
// verifies the final handle path and file identity, and keeps that exact object
// pinned until Close. FILE_FLAG_OPEN_REPARSE_POINT prevents a final-component
// reparse point from being followed during legacy-owner inspection.
func openPinnedWindowsSSHFile(path string, extraAccess uint32) (*pinnedWindowsSSHFile, bool, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return nil, false, ErrOpenSSHConfigConflict
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	handle, err := windows.CreateFile(pointer, access|extraAccess, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return nil, false, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || information.NumberOfLinks != 1 || !windowsSSHHandlePathMatches(handle, path) {
		windows.CloseHandle(handle)
		return nil, false, ErrOpenSSHConfigConflict
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, false, ErrOpenSSHConfigConflict
	}
	value, err := io.ReadAll(io.LimitReader(file, maxOpenSSHConfigSize+1))
	if err != nil || len(value) > maxOpenSSHConfigSize || bytes.IndexByte(value, 0) >= 0 {
		closeErr := file.Close()
		return nil, false, errors.Join(ErrOpenSSHConfigConflict, err, closeErr)
	}
	return &pinnedWindowsSSHFile{file: file, handle: handle, value: value}, true, nil
}

func windowsSSHHandlePathMatches(handle windows.Handle, expected string) bool {
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil || n == 0 {
			return false
		}
		if n < uint32(len(buffer)) {
			actual := windows.UTF16ToString(buffer[:n])
			if strings.HasPrefix(actual, `\\?\UNC\`) {
				actual = `\\` + strings.TrimPrefix(actual, `\\?\UNC\`)
			} else {
				actual = strings.TrimPrefix(actual, `\\?\`)
			}
			actualPath, actualErr := filepath.Abs(actual)
			expectedPath, expectedErr := filepath.Abs(expected)
			return actualErr == nil && expectedErr == nil && strings.EqualFold(filepath.Clean(actualPath), filepath.Clean(expectedPath))
		}
		if n >= 32768 {
			return false
		}
		buffer = make([]uint16, n+1)
	}
}

func migrateLegacyWindowsManagedSSHState(directory, sid string) error {
	userSID, err := windows.StringToSid(sid)
	if err != nil || userSID == nil || !userSID.IsValid() {
		return ErrOpenSSHConfigConflict
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	type stateFile struct {
		name  string
		owned bool
		file  *pinnedWindowsSSHFile
		admin bool
	}
	files := []*stateFile{
		{name: "config"},
		{name: "paperboat_config", owned: true},
		{name: ".paperboat-config-install-v1.json", owned: true},
		{name: ManagedIdentityPublicKeyFilename, owned: true},
	}
	defer func() {
		for _, state := range files {
			_ = state.file.Close()
		}
	}()
	anyAdministratorsOwner := false
	for _, state := range files {
		state.file, _, err = openPinnedWindowsSSHFile(filepath.Join(directory, state.name), windows.WRITE_OWNER)
		if err != nil {
			return err
		}
		if state.file == nil {
			continue
		}
		switch {
		case windowssecurity.HandleOwnerMatchesSID(state.file.handle, userSID):
		case windowssecurity.HandleOwnerMatchesSID(state.file.handle, administrators):
			state.admin = true
			anyAdministratorsOwner = true
		default:
			return ErrOpenSSHConfigConflict
		}
		if state.owned && !windowssecurity.ProtectedHandleDACLMatches(state.file.handle, managedSSHSDDL(sid)) {
			return ErrOpenSSHConfigConflict
		}
	}
	if !anyAdministratorsOwner {
		return nil
	}
	for _, state := range files {
		if state.file == nil {
			return ErrOpenSSHConfigConflict
		}
	}
	transaction, exists, err := openPinnedWindowsSSHFile(filepath.Join(directory, ".paperboat-config-transaction-v1.json"), 0)
	if err != nil {
		return err
	}
	if transaction != nil {
		_ = transaction.Close()
	}
	if exists {
		return ErrOpenSSHConfigConflict
	}

	main, owned, recordFile, identity := files[0], files[1], files[2], files[3]
	record, err := parseWindowsSSHRecord(recordFile.file.value)
	if err != nil || !validAliasSuffix(record.AliasSuffix) {
		return ErrOpenSSHConfigConflict
	}
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	if !validRecordedInclude(record.IncludeChunk, includeLine) || bytes.Count(main.file.value, []byte(record.IncludeChunk)) != 1 || !validOwnedOpenSSHContent(owned.file.value, record.AliasSuffix) || record.OwnedHash != hashOpenSSHBytes(owned.file.value) || !isManagedIdentityPublicKey(identity.file.value, "") {
		return ErrOpenSSHConfigConflict
	}
	if main.admin {
		if record.MainExisted || !bytes.Equal(main.file.value, []byte(record.IncludeChunk)) || !windowssecurity.ProtectedHandleDACLMatches(main.file.handle, managedSSHSDDL(sid)) {
			return ErrOpenSSHConfigConflict
		}
	}
	for _, state := range files {
		if !state.admin {
			continue
		}
		if err := migratePinnedWindowsSSHOwner(state.file, userSID, administrators, sid); err != nil {
			return fmt.Errorf("migrate managed SSH owner for %s: %w", state.name, err)
		}
	}
	for _, state := range files {
		if !windowssecurity.HandleOwnerMatchesSID(state.file.handle, userSID) || state.owned && !windowssecurity.ProtectedHandleDACLMatches(state.file.handle, managedSSHSDDL(sid)) {
			return ErrOpenSSHConfigConflict
		}
	}
	return nil
}

func migratePinnedWindowsSSHOwner(pinned *pinnedWindowsSSHFile, userSID, administrators *windows.SID, sid string) error {
	if pinned == nil || !windowssecurity.HandleOwnerMatchesSID(pinned.handle, administrators) || !windowssecurity.ProtectedHandleDACLMatches(pinned.handle, managedSSHSDDL(sid)) {
		return ErrOpenSSHConfigConflict
	}
	if err := windows.SetSecurityInfo(pinned.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, userSID, nil, nil, nil); err != nil {
		return err
	}
	if !windowssecurity.HandleOwnerMatchesSID(pinned.handle, userSID) || !windowssecurity.ProtectedHandleDACLMatches(pinned.handle, managedSSHSDDL(sid)) {
		return ErrOpenSSHConfigConflict
	}
	return nil
}

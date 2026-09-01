//go:build unix

package releaseeligibility

import (
	"os"
	"reflect"
)

func createTemporaryFile(directory, base string) (*os.File, string, error) {
	//paperboat:allow-source-policy atomic-replacement owner=release-eligibility reason=same-directory-private-owned-state-staging
	file, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return nil, "", err
	}
	return file, file.Name(), nil
}

// validateParentSecurity validates the directory containing the record without
// following the final path component. Ancestors may be platform-managed links
// (for example, /var on macOS), but the writable directory itself must be a
// real, private directory owned by this updater process.
func validateParentSecurity(path string, _ os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	if info.Mode().Perm()&0o022 != 0 || !ownedByCurrentUser(info) {
		return ErrUnsafePath
	}
	return nil
}

func validateRecordSecurity(_ string, info os.FileInfo) error {
	if info == nil || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return ErrUnsafePath
	}
	return nil
}

// secureRecordFile is intentionally a no-op on Unix. The staging file is
// created with 0600 in a directory that was checked for private ownership;
// rename therefore preserves the complete Unix security boundary.
func secureRecordFile(string) error { return nil }

func ownedByCurrentUser(info os.FileInfo) bool {
	uid, ok := ownerUID(info)
	return ok && uid == uint64(os.Geteuid())
}

// ownerUID uses the standard Stat_t Uid field through reflection because the
// field's concrete type differs between Linux and Darwin. It remains strictly
// fail-closed if an unsupported Unix target does not expose that field.
func ownerUID(info os.FileInfo) (uint64, bool) {
	if info == nil || info.Sys() == nil {
		return 0, false
	}
	value := reflect.ValueOf(info.Sys())
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Uid")
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint(), true
	default:
		return 0, false
	}
}

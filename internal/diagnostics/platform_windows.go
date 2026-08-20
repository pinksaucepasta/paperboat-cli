//go:build windows

package diagnostics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

func resolveDiagnosticOwner(config DiskConfig) (diagnosticOwner, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return diagnosticOwner{}, fmt.Errorf("%w: resolve current Windows SID", ErrInvalid)
	}
	sid := user.User.Sid.String()
	if config.OwnerSID != "" {
		supplied, parseErr := windows.StringToSid(config.OwnerSID)
		if parseErr != nil || !supplied.Equals(user.User.Sid) {
			return diagnosticOwner{}, ErrInvalid
		}
		sid = supplied.String()
	}
	return diagnosticOwner{sid: sid}, nil
}

func diagnosticSDDL(owner diagnosticOwner) string {
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + owner.sid + ")"
}

func ensureDiagnosticDirectory(path string, owner diagnosticOwner) error {
	if err := rejectReparseAncestors(path); err != nil {
		return fmt.Errorf("%w: validate diagnostic path before create", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := rejectReparseAncestors(path); err != nil {
		return fmt.Errorf("%w: validate diagnostic path after create", err)
	}
	if err := applyDiagnosticACL(path, owner); err != nil {
		return fmt.Errorf("%w: apply diagnostic ACL", err)
	}
	if err := verifyDiagnosticDirectory(path, owner); err != nil {
		return fmt.Errorf("%w: verify diagnostic ACL", err)
	}
	return nil
}

func verifiedDiagnosticFile(path string, owner diagnosticOwner) (os.FileInfo, error) {
	if err := rejectReparseAncestors(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !validDiagnosticFile(path, info, owner) {
		return nil, ErrInvalid
	}
	return info, nil
}

func validDiagnosticFile(path string, info os.FileInfo, owner diagnosticOwner) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && !isReparsePoint(path) && verifyDiagnosticACL(path, owner) == nil
}

func createDiagnosticSegment(path string, owner diagnosticOwner) error {
	return writeDiagnosticAtomic(path, nil, owner)
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
	return os.Remove(path)
}

func writeDiagnosticAtomic(path string, value []byte, owner diagnosticOwner) error {
	if err := ensureDiagnosticDirectory(filepath.Dir(path), owner); err != nil {
		return err
	}
	if err := atomicfile.Write(path, value, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: diagnosticSDDL(owner)}); err != nil {
		return err
	}
	_, err := verifiedDiagnosticFile(path, owner)
	return err
}

func syncDirectory(_ string) error { return nil }

func rejectReparseAncestors(path string) error {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: invalid Windows path", ErrInvalid)
	}
	current := volume + string(filepath.Separator)
	relative, err := filepath.Rel(current, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: path is outside volume", ErrInvalid)
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(current) {
			return fmt.Errorf("%w: diagnostic path contains reparse point", ErrInvalid)
		}
	}
	return nil
}

func isReparsePoint(path string) bool {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func verifyDiagnosticDirectory(path string, owner diagnosticOwner) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || isReparsePoint(path) {
		return ErrInvalid
	}
	return verifyDiagnosticACL(path, owner)
}

func applyDiagnosticACL(path string, owner diagnosticOwner) error {
	descriptor, err := windows.SecurityDescriptorFromString(diagnosticSDDL(owner))
	if err != nil {
		return err
	}
	abs, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := abs.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func verifyDiagnosticACL(path string, owner diagnosticOwner) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return ErrInvalid
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrInvalid
	}
	want, err := windows.SecurityDescriptorFromString(diagnosticSDDL(owner))
	if err != nil || daclPart(descriptor.String()) != daclPart(want.String()) {
		return ErrInvalid
	}
	return nil
}

func daclPart(value string) string {
	index := strings.Index(value, "D:")
	if index < 0 {
		return ""
	}
	// Windows may add the AI control bit when it materializes an inherited
	// descriptor. The protected-DACL bit is checked separately above; compare
	// the complete ACE sequence so no additional principal can be admitted.
	open := strings.IndexByte(value[index:], '(')
	if open < 0 {
		return ""
	}
	return "D:" + value[index+open:]
}

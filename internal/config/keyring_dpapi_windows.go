//go:build windows

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	cryptProtectUIForbidden  = 1
	cryptProtectLocalMachine = 4
)

var keyringDPAPIV2Magic = []byte{'P', 'B', 'K', 'R'}
var keyringDPAPITombstoneMagic = []byte{'P', 'B', 'K', 'D'}

var errDPAPISecretDeleted = errors.New("DPAPI credential was deleted")

const keyringDPAPIV2FixedHeaderSize = 4 + 1 + 1 + sha256.Size
const keyringDPAPITombstoneSize = 4 + 1 + sha256.Size

func dpapiSecretPath(ref string) (string, string, error) {
	if ref == "" || len(ref) > 1024 || strings.ContainsAny(ref, "\x00\r\n") {
		return "", "", ErrCredentialStoreUnavailable
	}
	directory, err := dpapiCredentialDirectory()
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(ref))
	return filepath.Join(directory, hex.EncodeToString(digest[:])+".dpapi"), directory, nil
}

func dpapiCredentialDirectory() (string, error) {
	base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if base == "" || !filepath.IsAbs(base) {
		return "", ErrCredentialStoreUnavailable
	}
	return filepath.Join(filepath.Clean(base), "Paperboat", "credentials"), nil
}

func currentUserCredentialSDDL() (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid.String() + ")", nil
}

func currentUserSID() (*windows.SID, error) {
	token, err := currentEffectiveUserToken()
	if err != nil {
		return nil, fmt.Errorf("%w: open current Windows token: %v", ErrCredentialStoreUnavailable, err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, fmt.Errorf("%w: resolve current Windows SID: %v", ErrCredentialStoreUnavailable, err)
	}
	return user.User.Sid, nil
}

func currentEffectiveUserToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return 0, err
	}
	return windows.OpenCurrentProcessToken()
}

func ensureDPAPIDirectory(path, sddl string) error {
	return ensureDPAPIDirectoryWithCreate(path, sddl, createDPAPIDirectoryHandle)
}

type dpapiDirectoryCreateFunc func(windows.Handle, string, string) (windows.Handle, windows.ByHandleFileInformation, string, error)

// ensureDPAPIDirectoryWithCreate accepts a creator so native tests can reproduce
// the default descriptor assigned by elevated SSH and network tokens without
// depending on the token that happens to run the test process.
func ensureDPAPIDirectoryWithCreate(path, sddl string, create dpapiDirectoryCreateFunc) error {
	if create == nil {
		return ErrCredentialStoreUnavailable
	}
	_, statErr := os.Lstat(path)
	existed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}

	parentHandle, parentPath, trustedParent := openVerifiedDPAPICredentialParent(path, ownerSID, sddl)
	if parentHandle != 0 {
		defer windows.CloseHandle(parentHandle)
	}

	var handle windows.Handle
	var information windows.ByHandleFileInformation
	var finalPath string
	createdBelowTrustedParent := false
	if !existed {
		if trustedParent {
			handle, information, finalPath, err = create(parentHandle, path, sddl)
			if err == nil {
				createdBelowTrustedParent = true
			} else if !dpapiObjectAlreadyExists(err) {
				return err
			}
		} else if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}

	if handle == 0 {
		handle, information, finalPath, err = openDPAPISecurityObject(path, false)
		if err != nil {
			return errors.Join(ErrCredentialStoreUnavailable, err)
		}
	}
	defer windows.CloseHandle(handle)
	if trustedParent && filepath.Dir(finalPath) != parentPath {
		return fmt.Errorf("%w: credential directory escaped its verified parent", ErrCredentialStoreUnavailable)
	}

	ownerMatches := windowssecurity.HandleOwnerMatchesSID(handle, ownerSID)
	if !ownerMatches {
		trustedLegacy := trustedLegacyDPAPIHandle(handle, information, ownerSID)
		trustedNetworkLayout := trustedParent && transientDPAPICredentialSubdirectory(path) && trustedNetworkDPAPIDirectoryHandle(handle, information)
		if !createdBelowTrustedParent && !trustedLegacy && !trustedNetworkLayout && !dpapiHandlePrivate(handle, ownerSID, sddl) {
			return fmt.Errorf("%w: refusing to change a foreign-owned credential directory", ErrCredentialStoreUnavailable)
		}
	}
	if err := applyDPAPIObjectSecurityHandle(handle, ownerSID, sddl); err != nil {
		return fmt.Errorf("%w: secure credential directory: %v", ErrCredentialStoreUnavailable, err)
	}
	if !dpapiHandlePrivate(handle, ownerSID, sddl) {
		return fmt.Errorf("%w: credential directory owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

// openVerifiedDPAPICredentialParent pins the exact default credential root
// without delete sharing. Only its direct children can use the narrow
// elevated/network-token migration. The Paperboat root itself never enters
// this path.
func openVerifiedDPAPICredentialParent(path string, userSID *windows.SID, sddl string) (windows.Handle, string, bool) {
	credentialDirectory, err := dpapiCredentialDirectory()
	if err != nil || !strings.EqualFold(filepath.Clean(filepath.Dir(path)), filepath.Clean(credentialDirectory)) {
		return 0, "", false
	}
	handle, _, finalPath, err := openDPAPISecurityObject(credentialDirectory, true)
	if err != nil {
		return 0, "", false
	}
	if !dpapiHandlePrivate(handle, userSID, sddl) {
		windows.CloseHandle(handle)
		return 0, "", false
	}
	return handle, finalPath, true
}

func transientDPAPICredentialSubdirectory(path string) bool {
	switch strings.ToLower(filepath.Base(filepath.Clean(path))) {
	case "pending-revocations", "transactions":
		return true
	default:
		return false
	}
}

// createDPAPIDirectoryHandle creates one child relative to the already pinned
// credential parent and returns the same handle used for the first security
// rewrite. There is no path-only interval in which the new name can be swapped.
func createDPAPIDirectoryHandle(parent windows.Handle, path, sddl string) (windows.Handle, windows.ByHandleFileInformation, string, error) {
	name := filepath.Base(filepath.Clean(path))
	if name == "." || name == ".." || strings.ContainsAny(name, `\/`) {
		return 0, windows.ByHandleFileInformation{}, "", ErrCredentialStoreUnavailable
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: absolute,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	var allocationSize int64
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.WRITE_DAC | windows.WRITE_OWNER)
	err = windows.NtCreateFile(&handle, access, attributes, &status, &allocationSize, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(absolute)
	runtime.KeepAlive(objectName)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	information, finalPath, err := inspectDPAPIDirectoryHandle(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	return handle, information, finalPath, nil
}

func dpapiObjectAlreadyExists(err error) bool {
	return err == windows.STATUS_OBJECT_NAME_COLLISION || errors.Is(err, os.ErrExist) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}

// openDPAPISecurityObject opens and pins one ordinary filesystem object while
// ownership and ACLs are inspected or changed. Omitting FILE_SHARE_DELETE keeps
// the verified object bound to its name until the migration finishes.
func openDPAPISecurityObject(path string, parentReadOnly bool) (windows.Handle, windows.ByHandleFileInformation, string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if !parentReadOnly {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	} else {
		access |= windows.FILE_TRAVERSE
	}
	handle, err := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	information, finalPath, err := inspectDPAPIDirectoryHandle(handle)
	if err != nil {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, "", err
	}
	return handle, information, finalPath, nil
}

func inspectDPAPIDirectoryHandle(handle windows.Handle) (windows.ByHandleFileInformation, string, error) {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return windows.ByHandleFileInformation{}, "", err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return windows.ByHandleFileInformation{}, "", errors.New("credential path is not an ordinary directory")
	}
	finalPath, err := dpapiFinalPath(handle)
	if err != nil {
		return windows.ByHandleFileInformation{}, "", err
	}
	return information, finalPath, nil
}

func openDPAPILegacyObject(path string, directory bool) (windows.Handle, windows.ByHandleFileInformation, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, windows.ByHandleFileInformation{}, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, err
	}
	isDirectory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory || !directory && information.NumberOfLinks != 1 {
		windows.CloseHandle(handle)
		return 0, windows.ByHandleFileInformation{}, errors.New("credential path is not an ordinary object")
	}
	return handle, information, nil
}

func dpapiFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			path := windows.UTF16ToString(buffer[:n])
			if strings.HasPrefix(path, `\\?\UNC\`) {
				path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
			} else {
				path = strings.TrimPrefix(path, `\\?\`)
			}
			return strings.ToLower(filepath.Clean(path)), nil
		}
		if n == 0 || n >= 32768 {
			return "", errors.New("credential path is too long")
		}
		buffer = make([]uint16, n+1)
	}
}

func dpapiHandlePrivate(handle windows.Handle, userSID *windows.SID, sddl string) bool {
	return userSID != nil && userSID.IsValid() && windowssecurity.HandleOwnerMatchesSID(handle, userSID) && windowssecurity.ProtectedHandleDACLMatches(handle, sddl)
}

// Older elevated Windows installs created per-user objects with Administrators
// as owner while granting only SYSTEM, Administrators, and the enrolled user
// full control. Preserve that exact transition, but validate it through the
// same pinned handle that will be changed.
func trustedLegacyDPAPIHandle(handle windows.Handle, information windows.ByHandleFileInformation, userSID *windows.SID) bool {
	if userSID == nil || !userSID.IsValid() {
		return false
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || !windowssecurity.HandleOwnerMatchesSID(handle, administrators) {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 3 {
		return false
	}
	protected := control&windows.SE_DACL_PROTECTED != 0
	const inheritedDirectoryFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.INHERITED_ACE
	expectedFlags := uint8(0)
	directory := information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	switch {
	case directory && !protected:
		expectedFlags = inheritedDirectoryFlags
	case directory && protected:
	case !directory && protected:
	default:
		return false
	}
	want := []*windows.SID{system, administrators, userSID}
	seen := make([]bool, len(want))
	const fileAllAccess windows.ACCESS_MASK = 0x001f01ff
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != fileAllAccess {
			return false
		}
		if ace.Header.AceFlags != expectedFlags {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for candidate, expected := range want {
			if !seen[candidate] && sid.IsValid() && sid.Equals(expected) {
				seen[candidate] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return seen[0] && seen[1] && seen[2]
}

// Elevated OpenSSH/network tokens use Administrators as their default owner and
// can create an unprotected directory with SYSTEM/Administrators full access
// plus read/execute for one transient logon SID. Only this exact, non-writable
// third ACE is eligible for adoption, and only beneath the pinned credential
// parent checked by ensureDPAPIDirectoryWithCreate.
func trustedNetworkDPAPIDirectoryHandle(handle windows.Handle, information windows.ByHandleFileInformation) bool {
	if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return false
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || !windowssecurity.HandleOwnerMatchesSID(handle, administrators) {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	defer runtime.KeepAlive(descriptor)
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 3 {
		return false
	}
	seenSystem, seenAdministrators, seenLogon := false, false, false
	const fileAllAccess windows.ACCESS_MASK = 0x001f01ff
	const networkReadExecute windows.ACCESS_MASK = 0x001200a9
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case !seenSystem && sid.IsValid() && sid.Equals(system) && ace.Mask == fileAllAccess:
			seenSystem = true
		case !seenAdministrators && sid.IsValid() && sid.Equals(administrators) && ace.Mask == fileAllAccess:
			seenAdministrators = true
		case !seenLogon && sid.IsValid() && transientLogonSID(sid) && ace.Mask == networkReadExecute:
			seenLogon = true
		default:
			return false
		}
	}
	return seenSystem && seenAdministrators && seenLogon
}

func transientLogonSID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	const prefix = "S-1-5-5-"
	value := sid.String()
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func applyDPAPIObjectSecurityHandle(handle windows.Handle, ownerSID *windows.SID, sddl string) error {
	if ownerSID == nil || !ownerSID.IsValid() {
		return ErrCredentialStoreUnavailable
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	runtime.KeepAlive(absolute)
	if !windowssecurity.ProtectedHandleDACLMatches(handle, sddl) {
		return errors.New("credential DACL did not match after rewrite")
	}
	if !windowssecurity.HandleOwnerMatchesSID(handle, ownerSID) {
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
			return err
		}
	}
	if !dpapiHandlePrivate(handle, ownerSID, sddl) {
		return errors.New("credential owner or DACL did not match after rewrite")
	}
	return nil
}

func migrateTrustedLegacyDPAPIObject(path, sddl string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	handle, information, err := openDPAPILegacyObject(path, info.IsDir())
	if err != nil {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	defer windows.CloseHandle(handle)
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if dpapiHandlePrivate(handle, ownerSID, sddl) {
		return nil
	}
	if !trustedLegacyDPAPIHandle(handle, information, ownerSID) && !dpapiHandlePrivate(handle, ownerSID, sddl) {
		return fmt.Errorf("%w: refusing to change a foreign-owned credential object", ErrCredentialStoreUnavailable)
	}
	if err := applyDPAPIObjectSecurityHandle(handle, ownerSID, sddl); err != nil {
		return fmt.Errorf("%w: migrate credential owner and DACL: %v", ErrCredentialStoreUnavailable, err)
	}
	return nil
}

func dpapiTransformWithEntropy(value, entropyBytes []byte, protect bool, protectFlags uint32) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(value))}
	if len(value) > 0 {
		input.Data = &value[0]
	}
	entropy := windows.DataBlob{Size: uint32(len(entropyBytes)), Data: &entropyBytes[0]}
	var output windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&input, nil, &entropy, 0, nil, cryptProtectUIForbidden|protectFlags, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, cryptProtectUIForbidden, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Size > windowsCredentialBlobMaxBytes*4 || output.Size > 0 && output.Data == nil {
		return nil, ErrCredentialStoreUnavailable
	}
	result := append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...)
	return result, nil
}

func dpapiTransform(value []byte, protect bool) ([]byte, error) {
	return dpapiTransformWithEntropy(value, []byte("paperboat/windows-keyring/v1"), protect, 0)
}

func keyringDPAPIV2Entropy(ref string) []byte {
	return append([]byte("paperboat/windows-keyring/v2\x00machine\x00"), keyringDPAPIV2RefHash(ref)...)
}

func keyringDPAPIV2RefHash(ref string) []byte {
	digest := sha256.Sum256([]byte(ref))
	return digest[:]
}

func keyringDPAPITombstone(ref string) []byte {
	marker := make([]byte, 0, keyringDPAPITombstoneSize)
	marker = append(marker, keyringDPAPITombstoneMagic...)
	marker = append(marker, 1) // tombstone schema v1
	marker = append(marker, keyringDPAPIV2RefHash(ref)...)
	return marker
}

func keyringDPAPIV2Header(ref string, inner bool) []byte {
	magic := keyringDPAPIV2Magic
	if inner {
		magic = []byte{'P', 'B', 'K', 'I'}
	}
	header := make([]byte, 0, keyringDPAPIV2FixedHeaderSize)
	header = append(header, magic...)
	header = append(header, 2, 1) // schema v2, CRYPTPROTECT_LOCAL_MACHINE scope
	header = append(header, keyringDPAPIV2RefHash(ref)...)
	return header
}

func protectKeyringDPAPIV2(ref, value string) ([]byte, error) {
	innerHeader := keyringDPAPIV2Header(ref, true)
	plain := make([]byte, 0, len(innerHeader)+4+len(value))
	plain = append(plain, innerHeader...)
	plain = binary.LittleEndian.AppendUint32(plain, uint32(len(value)))
	plain = append(plain, value...)
	defer clear(plain)
	protected, err := dpapiTransformWithEntropy(plain, keyringDPAPIV2Entropy(ref), true, cryptProtectLocalMachine)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, keyringDPAPIV2FixedHeaderSize+len(protected))
	result = append(result, keyringDPAPIV2Header(ref, false)...)
	result = append(result, protected...)
	clear(protected)
	return result, nil
}

func unprotectKeyringDPAPIV2(ref string, protected []byte) (string, error) {
	outerHeader := keyringDPAPIV2Header(ref, false)
	if len(protected) <= len(outerHeader) || !bytes.Equal(protected[:len(outerHeader)], outerHeader) {
		return "", fmt.Errorf("%w: unsupported DPAPI credential scope or schema", ErrCredentialStoreUnavailable)
	}
	plain, err := dpapiTransformWithEntropy(protected[len(outerHeader):], keyringDPAPIV2Entropy(ref), false, 0)
	if err != nil {
		return "", fmt.Errorf("%w: decrypt machine-scope DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(plain)
	innerHeader := keyringDPAPIV2Header(ref, true)
	if len(plain) < len(innerHeader)+4 || !bytes.Equal(plain[:len(innerHeader)], innerHeader) {
		return "", fmt.Errorf("%w: invalid machine-scope DPAPI credential envelope", ErrCredentialStoreUnavailable)
	}
	valueLength := int(binary.LittleEndian.Uint32(plain[len(innerHeader) : len(innerHeader)+4]))
	value := plain[len(innerHeader)+4:]
	if valueLength == 0 || valueLength != len(value) || valueLength > windowsCredentialBlobMaxBytes {
		return "", fmt.Errorf("%w: invalid machine-scope DPAPI credential length", ErrCredentialStoreUnavailable)
	}
	return string(value), nil
}

func setDPAPISecret(ref, value string, credentialErr error) error {
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	if err := ensureDPAPIDirectory(filepath.Dir(directory), sddl); err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	protected, err := protectKeyringDPAPIV2(ref, value)
	if err != nil {
		return errors.Join(windowsCredentialError("write", credentialErr), err)
	}
	defer clear(protected)
	if err := atomicfile.Write(path, protected, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return fmt.Errorf("%w: write DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
		return fmt.Errorf("%w: set DPAPI credential owner: %v", ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(path) {
		return fmt.Errorf("%w: written DPAPI credential owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

// setDPAPISecretTombstone atomically replaces any authoritative secret with a
// ref-bound, non-secret marker. The marker prevents a later interactive logon
// from reviving a stale Credential Manager migration source when that legacy
// store is unavailable to the current S4U or network logon.
func setDPAPISecretTombstone(ref string) error {
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return err
	}
	if err := ensureDPAPIDirectory(filepath.Dir(directory), sddl); err != nil {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		return errors.Join(ErrCredentialStoreUnavailable, err)
	}
	marker := keyringDPAPITombstone(ref)
	if err := atomicfile.Write(path, marker, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return fmt.Errorf("%w: write DPAPI credential tombstone: %v", ErrCredentialStoreUnavailable, err)
	}
	ownerSID, err := currentUserSID()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, ownerSID, nil, nil, nil); err != nil {
		return fmt.Errorf("%w: set DPAPI credential tombstone owner: %v", ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(path) {
		return fmt.Errorf("%w: written DPAPI credential tombstone owner or ACL is invalid", ErrCredentialStoreUnavailable)
	}
	return nil
}

func getDPAPISecret(ref string, credentialErr error) (string, error) {
	path, directory, err := dpapiSecretPath(ref)
	if err != nil {
		return "", err
	}
	if err := validateCredentialDirectory(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrSecretNotFound
		}
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if err := validateCredentialDirectory(filepath.Dir(directory)); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	// v1 protected only the credentials directory. On upgrade, an ordinary
	// owner-owned, non-reparse Paperboat root can be hardened in place before
	// decrypting the legacy blob. ensureDPAPIDirectory checks ownership before
	// changing the DACL, so foreign-owned roots remain untouched and rejected.
	sddl, err := currentUserCredentialSDDL()
	if err != nil {
		return "", err
	}
	if err := ensureDPAPIDirectory(filepath.Dir(directory), sddl); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if err := ensureDPAPIDirectory(directory, sddl); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if !credentialFilePrivate(filepath.Dir(directory)) {
		return "", fmt.Errorf("%w: DPAPI credential root has an invalid owner or ACL", ErrCredentialStoreUnavailable)
	}
	if !credentialFilePrivate(directory) {
		return "", fmt.Errorf("%w: DPAPI credential directory has an invalid owner or ACL", ErrCredentialStoreUnavailable)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrSecretNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	if err := migrateTrustedLegacyDPAPIObject(path, sddl); err != nil {
		return "", err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.Join(ErrCredentialStoreUnavailable, err)
	}
	protected, err := os.ReadFile(path)
	if err != nil || len(protected) == 0 || len(protected) > windowsCredentialBlobMaxBytes*4 {
		return "", fmt.Errorf("%w: read DPAPI credential: %v", ErrCredentialStoreUnavailable, err)
	}
	defer clear(protected)
	if bytes.Equal(protected, keyringDPAPITombstone(ref)) {
		return "", errDPAPISecretDeleted
	}
	if bytes.HasPrefix(protected, []byte{'P', 'B', 'K', 'R'}) {
		return unprotectKeyringDPAPIV2(ref, protected)
	}
	plain, err := dpapiTransform(protected, false)
	if err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, ErrCredentialRequiresInteractiveLogin, fmt.Errorf("decrypt legacy user-scope DPAPI credential: %w", err))
	}
	defer clear(plain)
	if len(plain) <= 1 || plain[0] != 1 || len(plain)-1 > windowsCredentialBlobMaxBytes {
		return "", fmt.Errorf("%w: invalid legacy user-scope DPAPI credential envelope", ErrCredentialStoreUnavailable)
	}
	value := string(plain[1:])
	if err := setDPAPISecret(ref, value, credentialErr); err != nil {
		return "", errors.Join(ErrCredentialStoreUnavailable, fmt.Errorf("migrate legacy user-scope DPAPI credential: %w", err))
	}
	return value, nil
}

func deleteDPAPISecret(ref string) error {
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// deleteDPAPISecretTombstone removes only the marker written for this exact
// reference. If a concurrent Set already replaced it, preserve that new value
// and report the conflict instead of deleting it.
func deleteDPAPISecretTombstone(ref string) error {
	path, _, err := dpapiSecretPath(ref)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(body)
	if !bytes.Equal(body, keyringDPAPITombstone(ref)) {
		return fmt.Errorf("%w: DPAPI credential changed during deletion", ErrCredentialStoreUnavailable)
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

//go:build windows

package service

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This is Paperboat's own minimal Service-for-User implementation. It is
// intentionally restricted to the one enrolled SID stored in protected
// installation state; it is not a generic impersonation facility.
const (
	ownerS4USourceName = "PBHostd"
	lsaNetworkLogon    = int32(3)
	msvS4ULogon        = int32(12)
	kerbS4ULogon       = int32(12)
	profileNoUI        = uint32(1)
)

type lsaHandle windows.Handle

type lsaTokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

type lsaQuotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

type msvS4ULogonRequest struct {
	MessageType       int32
	Flags             uint32
	UserPrincipalName windows.NTUnicodeString
	DomainName        windows.NTUnicodeString
}

type kerbS4ULogonRequest struct {
	MessageType int32
	Flags       uint32
	ClientUPN   windows.NTUnicodeString
	ClientRealm windows.NTUnicodeString
}

type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

type loadedOwnerProfile struct {
	token windows.Token
	key   windows.Handle
}

func (p *loadedOwnerProfile) Close() error {
	if p == nil {
		return nil
	}
	var result error
	if p.key != 0 {
		unloaded := false
		deadline := time.Now().Add(15 * time.Second)
		for {
			err := unloadUserProfile(p.token, p.key)
			if err == nil {
				unloaded = true
				break
			}
			if !errors.Is(err, windows.ERROR_BUSY) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				result = errors.Join(result, err)
				break
			}
			if !time.Now().Before(deadline) {
				result = errors.Join(result, err)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !unloaded {
			return result
		}
		p.key = 0
	}
	if p.token != 0 {
		if err := p.token.Close(); err != nil {
			return errors.Join(result, err)
		}
		p.token = 0
	}
	return result
}

var (
	modSecur32 = windows.NewLazySystemDLL("secur32.dll")
	modAdvapi  = windows.NewLazySystemDLL("advapi32.dll")
	modUserenv = windows.NewLazySystemDLL("userenv.dll")

	procLsaRegisterLogonProcess = modSecur32.NewProc("LsaRegisterLogonProcess")
	procLsaDeregisterLogon      = modSecur32.NewProc("LsaDeregisterLogonProcess")
	procLsaLookupPackage        = modSecur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser            = modSecur32.NewProc("LsaLogonUser")
	procLsaFreeBuffer           = modSecur32.NewProc("LsaFreeReturnBuffer")
	procAdjustTokenPrivileges   = modAdvapi.NewProc("AdjustTokenPrivileges")
	procAllocateLUID            = modAdvapi.NewProc("AllocateLocallyUniqueId")
	procLoadUserProfile         = modUserenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile       = modUserenv.NewProc("UnloadUserProfile")
)

func s4uOwnerToken(ownerSID string) (windows.Token, uint32, *loadedOwnerProfile, error) {
	sid, err := windows.StringToSid(ownerSID)
	if err != nil || sid == nil || !sid.IsValid() {
		return 0, 0, nil, ErrWindowsServiceEntry
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return 0, 0, nil, fmt.Errorf("resolve enrolled S4U account: %w", err)
	}
	source, err := s4uLogon(account, domain)
	if err != nil {
		return 0, 0, nil, err
	}
	defer source.Close()
	var token windows.Token
	access := uint32(windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_DUPLICATE | windows.TOKEN_IMPERSONATE | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID | windows.TOKEN_ADJUST_PRIVILEGES)
	if err := windows.DuplicateTokenEx(source, access, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return 0, 0, nil, err
	}
	if err := validateOwnerToken(token, ownerSID); err != nil {
		_ = token.Close()
		return 0, 0, nil, err
	}
	profile, err := loadOwnerProfile(token, account, domain)
	if err != nil {
		_ = token.Close()
		return 0, 0, nil, fmt.Errorf("load enrolled owner profile: %w", err)
	}
	// A logged-out S4U workload deliberately has no WTS session. Session
	// logoff events must not terminate it; its Job Object owns shutdown.
	return token, ^uint32(0), profile, nil
}

func s4uLogon(account, domain string) (windows.Token, error) {
	processName, err := windows.NewNTString(ownerS4USourceName)
	if err != nil {
		return 0, err
	}
	var handle lsaHandle
	var mode uint32
	if status := lsaRegisterLogonProcess(processName, &handle, &mode); status != 0 {
		return 0, fmt.Errorf("register Paperboat S4U logon process: %w", status)
	}
	defer lsaDeregisterLogonProcess(handle)

	packageName := "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
	authInfo, authLength, keepAlive, err := localS4URequest(account)
	if err != nil {
		return 0, err
	}
	if domain != "" && !strings.EqualFold(domain, localComputerName()) {
		packageName = "Kerberos"
		authInfo, authLength, keepAlive, err = domainS4URequest(domain + `\` + account)
		if err != nil {
			return 0, err
		}
	}
	pkg, err := windows.NewNTString(packageName)
	if err != nil {
		return 0, err
	}
	var packageID uint32
	if status := lsaLookupAuthenticationPackage(handle, pkg, &packageID); status != 0 {
		return 0, fmt.Errorf("resolve Paperboat S4U authentication package: %w", status)
	}
	var source lsaTokenSource
	copy(source.SourceName[:], ownerS4USourceName)
	if err := allocateLocallyUniqueID(&source.SourceIdentifier); err != nil {
		return 0, err
	}
	origin, err := windows.NewNTString(ownerS4USourceName)
	if err != nil {
		return 0, err
	}
	var profileBuffer uintptr
	var profileLength uint32
	var logonID windows.LUID
	var token windows.Token
	var quotas lsaQuotaLimits
	var subStatus windows.NTStatus
	status := lsaLogonUser(handle, origin, lsaNetworkLogon, packageID, authInfo, authLength, nil, &source, &profileBuffer, &profileLength, &logonID, &token, &quotas, &subStatus)
	runtime.KeepAlive(keepAlive)
	if profileBuffer != 0 {
		defer lsaFreeReturnBuffer(profileBuffer)
	}
	if status != 0 {
		return 0, fmt.Errorf("Paperboat S4U logon: %w (substatus %v)", status, subStatus)
	}
	return token, nil
}

func localS4URequest(account string) (unsafe.Pointer, uint32, any, error) {
	name, err := windows.UTF16FromString(account)
	if err != nil {
		return nil, 0, nil, err
	}
	domain := []uint16{'.', 0}
	storage := make([]byte, unsafe.Sizeof(msvS4ULogonRequest{})+uintptr(len(name)+len(domain))*unsafe.Sizeof(uint16(0)))
	request := (*msvS4ULogonRequest)(unsafe.Pointer(&storage[0]))
	request.MessageType = msvS4ULogon
	offset := unsafe.Sizeof(*request)
	request.UserPrincipalName, offset = copyUnicodeString(storage, offset, name)
	request.DomainName, _ = copyUnicodeString(storage, offset, domain)
	return unsafe.Pointer(request), uint32(len(storage)), storage, nil
}

func domainS4URequest(sam string) (unsafe.Pointer, uint32, any, error) {
	upn, err := samToUPN(sam)
	if err != nil {
		return nil, 0, nil, err
	}
	storage := make([]byte, unsafe.Sizeof(kerbS4ULogonRequest{})+uintptr(len(upn))*unsafe.Sizeof(uint16(0)))
	request := (*kerbS4ULogonRequest)(unsafe.Pointer(&storage[0]))
	request.MessageType = kerbS4ULogon
	request.ClientUPN, _ = copyUnicodeString(storage, unsafe.Sizeof(*request), upn)
	return unsafe.Pointer(request), uint32(len(storage)), storage, nil
}

func copyUnicodeString(storage []byte, offset uintptr, value []uint16) (windows.NTUnicodeString, uintptr) {
	if len(value) == 0 {
		return windows.NTUnicodeString{}, offset
	}
	pointer := (*uint16)(unsafe.Add(unsafe.Pointer(&storage[0]), offset))
	copy(unsafe.Slice(pointer, len(value)), value)
	return windows.NTUnicodeString{Length: uint16((len(value) - 1) * 2), MaximumLength: uint16(len(value) * 2), Buffer: pointer}, offset + uintptr(len(value))*unsafe.Sizeof(uint16(0))
}

func samToUPN(sam string) ([]uint16, error) {
	from, err := windows.UTF16PtrFromString(sam)
	if err != nil {
		return nil, err
	}
	var size uint32
	err = windows.TranslateName(from, windows.NameSamCompatible, windows.NameUserPrincipal, nil, &size)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if size < 2 {
		return nil, ErrWindowsServiceEntry
	}
	result := make([]uint16, size)
	if err := windows.TranslateName(from, windows.NameSamCompatible, windows.NameUserPrincipal, &result[0], &size); err != nil {
		return nil, err
	}
	return result, nil
}

func localComputerName() string {
	var buffer [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	size := uint32(len(buffer))
	if err := windows.GetComputerName(&buffer[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buffer[:size])
}

func loadOwnerProfile(token windows.Token, account, domain string) (*loadedOwnerProfile, error) {
	userName, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return nil, err
	}
	var serverName *uint16
	if domain != "" {
		serverName, err = windows.UTF16PtrFromString(domain)
		if err != nil {
			return nil, err
		}
	}
	info := profileInfo{Size: uint32(unsafe.Sizeof(profileInfo{})), Flags: profileNoUI, UserName: userName, ServerName: serverName}
	if err := loadUserProfile(token, &info); err != nil {
		return nil, err
	}
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(token), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = unloadUserProfile(token, info.Profile)
		return nil, err
	}
	return &loadedOwnerProfile{token: windows.Token(duplicate), key: info.Profile}, nil
}

func validateOwnerToken(token windows.Token, ownerSID string) error {
	want, err := windows.StringToSid(ownerSID)
	if err != nil || want == nil || !want.IsValid() {
		return ErrWindowsServiceEntry
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.Equals(want) {
		return ErrWindowsServiceEntry
	}
	return nil
}

func stripOwnerTokenPrivileges(token windows.Token) error {
	if err := adjustTokenPrivileges(token, true, nil); err != nil {
		return err
	}
	var privileges windows.Tokenprivileges
	privileges.PrivilegeCount = 1
	name, err := windows.UTF16PtrFromString("SeChangeNotifyPrivilege")
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, name, &privileges.Privileges[0].Luid); err != nil {
		return err
	}
	privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return adjustTokenPrivileges(token, false, &privileges)
}

// AdjustTokenPrivileges reports success even when one or more requested
// privileges were absent. The raw return's last-error value is authoritative
// for ERROR_NOT_ALL_ASSIGNED, so every enable and stripping operation uses it.
func adjustTokenPrivileges(token windows.Token, disableAll bool, privileges *windows.Tokenprivileges) error {
	var disable uintptr
	if disableAll {
		disable = 1
	}
	result, _, callErr := syscall.SyscallN(procAdjustTokenPrivileges.Addr(), uintptr(token), disable, uintptr(unsafe.Pointer(privileges)), 0, 0, 0)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return windows.ERROR_GEN_FAILURE
	}
	if callErr == windows.ERROR_NOT_ALL_ASSIGNED {
		return windows.ERROR_NOT_ALL_ASSIGNED
	}
	return nil
}

func enableOwnerLaunchPrivileges() (func(), error) {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	cleanup := func() {
		if err := windows.RevertToSelf(); err != nil {
			panic(fmt.Sprintf("Paperboat owner-token launch could not revert thread impersonation: %v", err))
		}
		runtime.UnlockOSThread()
	}
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &token); err != nil {
		cleanup()
		return nil, err
	}
	defer token.Close()
	// LoadUserProfile requires backup/restore privileges; LsaLogonUser and
	// CreateProcessAsUser require the remaining privileges when hostd runs as
	// LocalSystem. Enable each explicitly and fail on NOT_ALL_ASSIGNED.
	names := []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"}
	bytes := make([]byte, unsafe.Sizeof(windows.Tokenprivileges{})+uintptr(len(names)-1)*unsafe.Sizeof(windows.LUIDAndAttributes{}))
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&bytes[0]))
	privileges.PrivilegeCount = uint32(len(names))
	for index, value := range names {
		name, err := windows.UTF16PtrFromString(value)
		if err != nil {
			cleanup()
			return nil, err
		}
		if err := windows.LookupPrivilegeValue(nil, name, &privileges.AllPrivileges()[index].Luid); err != nil {
			cleanup()
			return nil, err
		}
		privileges.AllPrivileges()[index].Attributes = windows.SE_PRIVILEGE_ENABLED
	}
	if err := adjustTokenPrivileges(token, false, privileges); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}

func allocateLocallyUniqueID(luid *windows.LUID) error {
	result, _, callErr := syscall.SyscallN(procAllocateLUID.Addr(), uintptr(unsafe.Pointer(luid)))
	if result != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return windows.ERROR_GEN_FAILURE
}

func lsaRegisterLogonProcess(name *windows.NTString, handle *lsaHandle, mode *uint32) windows.NTStatus {
	result, _, _ := syscall.SyscallN(procLsaRegisterLogonProcess.Addr(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(handle)), uintptr(unsafe.Pointer(mode)))
	return windows.NTStatus(result)
}

func lsaDeregisterLogonProcess(handle lsaHandle) {
	_, _, _ = syscall.SyscallN(procLsaDeregisterLogon.Addr(), uintptr(handle))
}

func lsaLookupAuthenticationPackage(handle lsaHandle, name *windows.NTString, packageID *uint32) windows.NTStatus {
	result, _, _ := syscall.SyscallN(procLsaLookupPackage.Addr(), uintptr(handle), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(packageID)))
	return windows.NTStatus(result)
}

func lsaLogonUser(handle lsaHandle, origin *windows.NTString, logonType int32, packageID uint32, authInfo unsafe.Pointer, authLength uint32, groups *windows.Tokengroups, source *lsaTokenSource, profileBuffer *uintptr, profileLength *uint32, logonID *windows.LUID, token *windows.Token, quotas *lsaQuotaLimits, subStatus *windows.NTStatus) windows.NTStatus {
	result, _, _ := syscall.SyscallN(procLsaLogonUser.Addr(), uintptr(handle), uintptr(unsafe.Pointer(origin)), uintptr(logonType), uintptr(packageID), uintptr(authInfo), uintptr(authLength), uintptr(unsafe.Pointer(groups)), uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(profileBuffer)), uintptr(unsafe.Pointer(profileLength)), uintptr(unsafe.Pointer(logonID)), uintptr(unsafe.Pointer(token)), uintptr(unsafe.Pointer(quotas)), uintptr(unsafe.Pointer(subStatus)))
	return windows.NTStatus(result)
}

func lsaFreeReturnBuffer(buffer uintptr) {
	_, _, _ = syscall.SyscallN(procLsaFreeBuffer.Addr(), buffer)
}

func loadUserProfile(token windows.Token, info *profileInfo) error {
	result, _, callErr := syscall.SyscallN(procLoadUserProfile.Addr(), uintptr(token), uintptr(unsafe.Pointer(info)))
	if result != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return windows.ERROR_GEN_FAILURE
}

func unloadUserProfile(token windows.Token, key windows.Handle) error {
	result, _, callErr := syscall.SyscallN(procUnloadUserProfile.Addr(), uintptr(token), uintptr(key))
	if result != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return windows.ERROR_GEN_FAILURE
}

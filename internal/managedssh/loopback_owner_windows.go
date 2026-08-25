//go:build windows

package managedssh

import (
	"context"
	"errors"
	"math/bits"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsTCPTableOwnerPIDAll = 5
	windowsTCPStateEstablished = 5
	windowsLoopbackOwnerWait   = 250 * time.Millisecond
	windowsMaximumTCPTableSize = 10 << 20
)

var (
	windowsIPHLPAPI            = windows.NewLazySystemDLL("iphlpapi.dll")
	windowsGetExtendedTCPTable = windowsIPHLPAPI.NewProc("GetExtendedTcpTable")
)

type windowsTCPRowOwnerPID struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
	pid        uint32
}

// verifyWindowsSSHLoopbackOwner proves that the accepted socket's client end
// belongs to the exact ssh.exe child before exposing the authenticated stream.
// A local process that races the ephemeral listener can only force a failure.
func verifyWindowsSSHLoopbackOwner(ctx context.Context, connection *net.TCPConn, expectedPID uint32) error {
	if ctx == nil || connection == nil || expectedPID == 0 {
		return ErrSSHLoopbackOwner
	}
	client, clientOK := connection.RemoteAddr().(*net.TCPAddr)
	proxy, proxyOK := connection.LocalAddr().(*net.TCPAddr)
	if !clientOK || !proxyOK || !client.IP.IsLoopback() || !proxy.IP.IsLoopback() || client.Port <= 0 || proxy.Port <= 0 {
		return ErrSSHLoopbackOwner
	}
	deadline := time.Now().Add(windowsLoopbackOwnerWait)
	for {
		owner, found, err := windowsTCPConnectionOwner(client, proxy)
		if err != nil {
			return errors.Join(ErrSSHLoopbackOwner, err)
		}
		if found {
			if owner == expectedPID {
				return nil
			}
			return ErrSSHLoopbackOwner
		}
		if !time.Now().Before(deadline) {
			return ErrSSHLoopbackOwner
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func windowsTCPConnectionOwner(client, proxy *net.TCPAddr) (uint32, bool, error) {
	clientIPv4, proxyIPv4 := client.IP.To4(), proxy.IP.To4()
	if clientIPv4 == nil || proxyIPv4 == nil {
		return 0, false, ErrSSHLoopbackOwner
	}
	var (
		size   uint32
		buffer []byte
	)
	for {
		var address uintptr
		if len(buffer) > 0 {
			address = uintptr(unsafe.Pointer(&buffer[0]))
		}
		result, _, _ := windowsGetExtendedTCPTable.Call(address, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, windowsTCPTableOwnerPIDAll, 0)
		if result == 0 {
			break
		}
		if result != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > windowsMaximumTCPTableSize {
			return 0, false, windows.Errno(result)
		}
		buffer = make([]byte, size)
	}
	if size < 4 || int(size) > len(buffer) || len(buffer) < 4 {
		return 0, false, ErrSSHLoopbackOwner
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := int(unsafe.Sizeof(windowsTCPRowOwnerPID{}))
	if uint64(count) > uint64((int(size)-4)/rowSize) {
		return 0, false, ErrSSHLoopbackOwner
	}
	rows := unsafe.Slice((*windowsTCPRowOwnerPID)(unsafe.Pointer(&buffer[4])), int(count))
	for _, row := range rows {
		if row.state != windowsTCPStateEstablished || windowsTCPAddress(row.localAddr) != [4]byte(clientIPv4) || windowsTCPPort(row.localPort) != uint16(client.Port) || windowsTCPAddress(row.remoteAddr) != [4]byte(proxyIPv4) || windowsTCPPort(row.remotePort) != uint16(proxy.Port) {
			continue
		}
		return row.pid, true, nil
	}
	return 0, false, nil
}

func windowsTCPAddress(value uint32) [4]byte {
	value = bits.ReverseBytes32(value)
	return [4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}

func windowsTCPPort(value uint32) uint16 {
	return uint16(bits.ReverseBytes32(value) >> 16)
}

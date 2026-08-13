package udpsocket

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

var ErrPathErrorUnsupported = errors.New("UDP path error queue unsupported")

type Family uint8

const (
	FamilyIPv4 Family = iota + 1
	FamilyIPv6
)

type PathErrorKind uint8

const (
	PathErrorOther PathErrorKind = iota + 1
	PathErrorPacketTooBig
)

type PathError struct {
	Kind   PathErrorKind
	Family Family
	MTU    uint32
	Errno  syscall.Errno
	Origin uint8
	Type   uint8
	Code   uint8
}

func ReadPathError(connection *net.UDPConn) (PathError, bool, error) {
	if connection == nil {
		return PathError{}, false, ErrInvalid
	}
	return readPathError(connection)
}

func decodeLinuxExtendedError(family Family, value []byte) (PathError, error) {
	if family != FamilyIPv4 && family != FamilyIPv6 || len(value) < 16 {
		return PathError{}, ErrInvalid
	}
	result := PathError{
		Kind: PathErrorOther, Family: family,
		Errno:  syscall.Errno(binary.NativeEndian.Uint32(value[0:4])),
		Origin: value[4], Type: value[5], Code: value[6],
		MTU: binary.NativeEndian.Uint32(value[8:12]),
	}
	const (
		originLocal                = 1
		originICMP                 = 2
		originICMP6                = 3
		icmpDestinationUnreachable = 3
		icmpFragmentationNeeded    = 4
		icmpv6PacketTooBig         = 2
	)
	packetTooBig := result.Errno == syscall.EMSGSIZE && (result.Origin == originLocal ||
		family == FamilyIPv4 && result.Origin == originICMP && result.Type == icmpDestinationUnreachable && result.Code == icmpFragmentationNeeded ||
		family == FamilyIPv6 && result.Origin == originICMP6 && result.Type == icmpv6PacketTooBig && result.Code == 0)
	if packetTooBig {
		result.Kind = PathErrorPacketTooBig
		if result.MTU == 0 {
			return PathError{}, errors.New("packet-too-big path error omitted MTU")
		}
	} else {
		result.MTU = 0
	}
	return result, nil
}

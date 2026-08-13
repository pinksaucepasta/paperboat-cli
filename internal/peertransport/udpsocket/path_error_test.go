package udpsocket

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
)

func TestDecodeLinuxPacketTooBigVariants(t *testing.T) {
	tests := []struct {
		name   string
		family Family
		origin uint8
		kind   uint8
		code   uint8
	}{
		{name: "local IPv4", family: FamilyIPv4, origin: 1},
		{name: "local IPv6", family: FamilyIPv6, origin: 1},
		{name: "ICMP fragmentation needed", family: FamilyIPv4, origin: 2, kind: 3, code: 4},
		{name: "ICMPv6 packet too big", family: FamilyIPv6, origin: 3, kind: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := extendedErrorBytes(syscall.EMSGSIZE, test.origin, test.kind, test.code, 1380)
			result, err := decodeLinuxExtendedError(test.family, value)
			if err != nil {
				t.Fatal(err)
			}
			if result.Kind != PathErrorPacketTooBig || result.MTU != 1380 || result.Family != test.family || result.Errno != syscall.EMSGSIZE {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestReadPathErrorReportsPlatformCapability(t *testing.T) {
	set, err := Open(context.Background(), DevelopmentConfig(true, false))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	_, found, err := ReadPathError(set.IPv4())
	if SupportsPathErrors() {
		if err != nil || found {
			t.Fatalf("empty Linux queue found=%v error=%v", found, err)
		}
	} else if !errors.Is(err, ErrPathErrorUnsupported) || found {
		t.Fatalf("unsupported queue found=%v error=%v", found, err)
	}
}

func TestDecodeLinuxPreservesUnrelatedErrorsWithoutMTU(t *testing.T) {
	value := extendedErrorBytes(syscall.ECONNREFUSED, 2, 3, 3, 9999)
	result, err := decodeLinuxExtendedError(FamilyIPv4, value)
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != PathErrorOther || result.MTU != 0 || result.Errno != syscall.ECONNREFUSED || result.Type != 3 || result.Code != 3 {
		t.Fatalf("result=%+v", result)
	}
}

func TestDecodeLinuxRejectsMissingMTUAndMalformedInput(t *testing.T) {
	missing := extendedErrorBytes(syscall.EMSGSIZE, 1, 0, 0, 0)
	if _, err := decodeLinuxExtendedError(FamilyIPv4, missing); err == nil {
		t.Fatal("packet-too-big without MTU accepted")
	}
	if _, err := decodeLinuxExtendedError(FamilyIPv4, make([]byte, 15)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short input error=%v", err)
	}
	if _, err := decodeLinuxExtendedError(0, make([]byte, 16)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("family error=%v", err)
	}
}

func extendedErrorBytes(errno syscall.Errno, origin, kind, code uint8, mtu uint32) []byte {
	value := make([]byte, 16)
	binary.NativeEndian.PutUint32(value[0:4], uint32(errno))
	value[4], value[5], value[6] = origin, kind, code
	binary.NativeEndian.PutUint32(value[8:12], mtu)
	return value
}

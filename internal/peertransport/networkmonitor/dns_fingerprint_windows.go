//go:build windows

package networkmonitor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxWindowsDNSBuffer = 1 << 20

// SystemDNSFingerprint reads Windows DNS server addresses through the native
// IP Helper API. Only sorted normalized addresses enter the local digest.
func SystemDNSFingerprint(ctx context.Context) ([32]byte, error) {
	if err := validateDNSContext(ctx); err != nil {
		return [32]byte{}, err
	}
	size := uint32(16 << 10)
	var buffer []byte
	for attempt := 0; attempt < 3; attempt++ {
		if size == 0 || uint64(size) > maxWindowsDNSBuffer {
			return [32]byte{}, ErrDNSUnavailable
		}
		buffer = make([]byte, size)
		errorCode := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])),
			&size,
		)
		if errorCode == nil {
			break
		}
		if errorCode != windows.ERROR_BUFFER_OVERFLOW {
			return [32]byte{}, fmt.Errorf("%w: GetAdaptersAddresses: %v", ErrDNSUnavailable, errorCode)
		}
		if attempt == 2 {
			return [32]byte{}, ErrDNSUnavailable
		}
	}
	if err := validateDNSContext(ctx); err != nil {
		return [32]byte{}, err
	}
	addresses := make(map[string]struct{})
	for adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		for dns := adapter.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			if normalized := normalizeWindowsDNSAddress(ip); normalized != "" {
				addresses[normalized] = struct{}{}
			}
		}
	}
	if len(addresses) == 0 {
		return [32]byte{}, ErrDNSUnavailable
	}
	values := make([]string, 0, len(addresses))
	for address := range addresses {
		values = append(values, address)
	}
	sort.Strings(values)
	return hashDNSFingerprint([]byte(strings.Join(values, "\x00")))
}

func normalizeWindowsDNSAddress(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if parsed := net.ParseIP(ip.String()); parsed != nil {
		return parsed.String()
	}
	return ""
}

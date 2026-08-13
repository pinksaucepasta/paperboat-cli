//go:build darwin && cgo

package httptransport

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdint.h>
#include <string.h>

typedef struct {
	int http_enabled;
	char http_host[1024];
	int http_port;
	int https_enabled;
	char https_host[1024];
	int https_port;
	int pac_enabled;
	int autodiscovery_enabled;
	int exclude_simple;
	char exceptions[4096];
} PBProxySnapshot;

static int pb_number(CFDictionaryRef values, CFStringRef key) {
	CFNumberRef number = (CFNumberRef)CFDictionaryGetValue(values, key);
	if (number == NULL || CFGetTypeID(number) != CFNumberGetTypeID()) return 0;
	int result = 0;
	CFNumberGetValue(number, kCFNumberIntType, &result);
	return result;
}

static void pb_string(CFDictionaryRef values, CFStringRef key, char *output, size_t size) {
	CFStringRef value = (CFStringRef)CFDictionaryGetValue(values, key);
	if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) return;
	CFStringGetCString(value, output, size, kCFStringEncodingUTF8);
}

static void pb_exceptions(CFDictionaryRef values, char *output, size_t size) {
	CFArrayRef exceptions = (CFArrayRef)CFDictionaryGetValue(values, kSCPropNetProxiesExceptionsList);
	if (exceptions == NULL || CFGetTypeID(exceptions) != CFArrayGetTypeID()) return;
	size_t used = 0;
	for (CFIndex i = 0; i < CFArrayGetCount(exceptions); i++) {
		CFStringRef value = (CFStringRef)CFArrayGetValueAtIndex(exceptions, i);
		if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) continue;
		char item[512] = {0};
		if (!CFStringGetCString(value, item, sizeof(item), kCFStringEncodingUTF8)) continue;
		size_t length = strlen(item);
		if (length == 0 || used + length + (used > 0 ? 1 : 0) >= size) continue;
		if (used > 0) output[used++] = ',';
		memcpy(output + used, item, length);
		used += length;
		output[used] = 0;
	}
}

static int pb_copy_system_proxy(PBProxySnapshot *output) {
	memset(output, 0, sizeof(*output));
	CFDictionaryRef values = SCDynamicStoreCopyProxies(NULL);
	if (values == NULL) return 0;
	output->http_enabled = pb_number(values, kSCPropNetProxiesHTTPEnable);
	pb_string(values, kSCPropNetProxiesHTTPProxy, output->http_host, sizeof(output->http_host));
	output->http_port = pb_number(values, kSCPropNetProxiesHTTPPort);
	output->https_enabled = pb_number(values, kSCPropNetProxiesHTTPSEnable);
	pb_string(values, kSCPropNetProxiesHTTPSProxy, output->https_host, sizeof(output->https_host));
	output->https_port = pb_number(values, kSCPropNetProxiesHTTPSPort);
	output->pac_enabled = pb_number(values, kSCPropNetProxiesProxyAutoConfigEnable);
	output->autodiscovery_enabled = pb_number(values, kSCPropNetProxiesProxyAutoDiscoveryEnable);
	output->exclude_simple = pb_number(values, kSCPropNetProxiesExcludeSimpleHostnames);
	pb_exceptions(values, output->exceptions, sizeof(output->exceptions));
	CFRelease(values);
	return 1;
}
*/
import "C"

import (
	"context"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
)

type NativeSystemProxySource struct{}

func (NativeSystemProxySource) Snapshot(ctx context.Context) (ProxySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProxySnapshot{}, err
	}
	var native C.PBProxySnapshot
	if C.pb_copy_system_proxy(&native) == 0 {
		return ProxySnapshot{}, nil
	}
	result := ProxySnapshot{
		NoProxy:            normalizeNativeExceptions(C.GoString(&native.exceptions[0])),
		ExcludeSimpleHosts: native.exclude_simple != 0,
		PACOnly:            native.pac_enabled != 0 || native.autodiscovery_enabled != 0,
	}
	if native.http_enabled != 0 {
		result.HTTPProxy = nativeProxyURL(C.GoString(&native.http_host[0]), int(native.http_port))
	}
	if native.https_enabled != 0 {
		result.HTTPSProxy = nativeProxyURL(C.GoString(&native.https_host[0]), int(native.https_port))
	}
	if result.HTTPProxy != "" || result.HTTPSProxy != "" {
		result.PACOnly = false
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(result.HTTPProxy + "\x00" + result.HTTPSProxy + "\x00" + result.NoProxy + "\x00" + strconv.FormatBool(result.ExcludeSimpleHosts) + "\x00" + strconv.FormatBool(result.PACOnly)))
	result.Generation = hash.Sum64()
	return result, nil
}

func normalizeNativeExceptions(value string) string {
	items := strings.Split(value, ",")
	result := items[:0]
	for _, item := range items {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(item, "*.") {
			item = "." + strings.TrimPrefix(item, "*.")
		}
		if item != "" && item != "<local>" {
			result = append(result, item)
		}
	}
	return strings.Join(result, ",")
}

func nativeProxyURL(host string, port int) string {
	if host == "" || port < 1 || port > 65535 {
		return ""
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

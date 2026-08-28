package windowsopenssh

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// deriveServiceSID implements the Windows service SID derivation used by SCM:
// SHA-1 of the upper-case UTF-16LE service name becomes five little-endian
// subauthorities beneath S-1-5-80.
func deriveServiceSID(serviceName string) string {
	codeUnits := utf16.Encode([]rune(strings.ToUpper(serviceName)))
	encodedName := make([]byte, len(codeUnits)*2)
	for index, codeUnit := range codeUnits {
		binary.LittleEndian.PutUint16(encodedName[index*2:], codeUnit)
	}
	digest := sha1.Sum(encodedName)
	return fmt.Sprintf(
		"S-1-5-80-%d-%d-%d-%d-%d",
		binary.LittleEndian.Uint32(digest[0:4]),
		binary.LittleEndian.Uint32(digest[4:8]),
		binary.LittleEndian.Uint32(digest[8:12]),
		binary.LittleEndian.Uint32(digest[12:16]),
		binary.LittleEndian.Uint32(digest[16:20]),
	)
}

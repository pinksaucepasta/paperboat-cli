// Package manifest validates the native Windows application manifest embedded
// in Paperboat executables.
package manifest

import (
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	assemblyNamespace      = "urn:schemas-microsoft-com:asm.v1"
	applicationNamespace   = "urn:schemas-microsoft-com:asm.v3"
	longPathAwareNamespace = "http://schemas.microsoft.com/SMI/2016/WindowsSettings"
	resourceManifestType   = 24
	resourceManifestID     = 1
)

// ValidateManifest checks the exact manifest contract required for Windows
// extended-length paths. It intentionally validates namespaces as well as the
// element value because a same-named element in another namespace is ignored
// by the Windows loader.
func ValidateManifest(data []byte) error {
	type longPathAware struct {
		Value string `xml:",chardata"`
	}
	type windowsSettings struct {
		LongPathAware longPathAware `xml:"http://schemas.microsoft.com/SMI/2016/WindowsSettings longPathAware"`
	}
	type application struct {
		WindowsSettings windowsSettings `xml:"urn:schemas-microsoft-com:asm.v3 windowsSettings"`
	}
	var value struct {
		XMLName     xml.Name    `xml:"urn:schemas-microsoft-com:asm.v1 assembly"`
		ManifestVer string      `xml:"manifestVersion,attr"`
		Application application `xml:"urn:schemas-microsoft-com:asm.v3 application"`
	}
	if err := xml.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode application manifest: %w", err)
	}
	if value.XMLName.Local != "assembly" || value.XMLName.Space != assemblyNamespace || value.ManifestVer != "1.0" {
		return errors.New("application manifest has an invalid assembly root")
	}
	if strings.TrimSpace(value.Application.WindowsSettings.LongPathAware.Value) != "true" {
		return errors.New("application manifest is not longPathAware")
	}
	return nil
}

// ValidatePE verifies that a Windows PE contains the RT_MANIFEST resource
// used by the loader. It does not execute the binary and works for both PE32+
// amd64 and arm64 artifacts.
func ValidatePE(data []byte) error {
	resource, err := manifestResource(data)
	if err != nil {
		return err
	}
	if err := ValidateManifest(resource); err == nil {
		return nil
	}
	decoded, err := decodeUTF16(resource)
	if err != nil {
		return fmt.Errorf("validate manifest resource: %w", err)
	}
	return ValidateManifest(decoded)
}

func manifestResource(data []byte) ([]byte, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errors.New("not a PE executable")
	}
	peOffset, ok := u32(data, 0x3c)
	if !ok || uint64(peOffset)+24 > uint64(len(data)) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, errors.New("invalid PE header")
	}
	coff := int(peOffset) + 4
	numberOfSections, ok := u16(data, coff+2)
	if !ok {
		return nil, errors.New("invalid PE section count")
	}
	optionalSize, ok := u16(data, coff+16)
	if !ok {
		return nil, errors.New("invalid PE optional-header size")
	}
	optional := coff + 20
	if optional < 0 || uint64(optional)+uint64(optionalSize) > uint64(len(data)) {
		return nil, errors.New("truncated PE optional header")
	}
	magic, ok := u16(data, optional)
	if !ok {
		return nil, errors.New("missing PE optional-header magic")
	}
	dataDirectory := optional + 96
	switch magic {
	case 0x10b:
		dataDirectory = optional + 96
	case 0x20b:
		dataDirectory = optional + 112
	default:
		return nil, fmt.Errorf("unsupported PE optional-header magic 0x%x", magic)
	}
	if dataDirectory < optional || dataDirectory+24 > optional+int(optionalSize) {
		return nil, errors.New("PE has no resource directory")
	}
	resourceRVA, ok := u32(data, dataDirectory+8*2)
	if !ok || resourceRVA == 0 {
		return nil, errors.New("PE has no RT_MANIFEST resource directory")
	}
	sections := sectionTable{data: data, offset: optional + int(optionalSize), count: int(numberOfSections)}
	resourceFileOffset, ok := sections.fileOffset(resourceRVA)
	if !ok {
		return nil, errors.New("PE resource directory is outside its sections")
	}
	return sections.findResource(resourceFileOffset, resourceFileOffset, []uint32{resourceManifestType, resourceManifestID, 0x409})
}

type sectionTable struct {
	data   []byte
	offset int
	count  int
}

func (s sectionTable) fileOffset(rva uint32) (int, bool) {
	for index := 0; index < s.count; index++ {
		offset := s.offset + index*40
		if offset < 0 || offset+40 > len(s.data) {
			return 0, false
		}
		virtualSize, ok := u32(s.data, offset+8)
		if !ok {
			return 0, false
		}
		virtualAddress, ok := u32(s.data, offset+12)
		if !ok {
			return 0, false
		}
		rawSize, ok := u32(s.data, offset+16)
		if !ok {
			return 0, false
		}
		rawPointer, ok := u32(s.data, offset+20)
		if !ok {
			return 0, false
		}
		span := virtualSize
		if rawSize > span {
			span = rawSize
		}
		if rva < virtualAddress || uint64(rva-virtualAddress) >= uint64(span) {
			continue
		}
		fileOffset := uint64(rawPointer) + uint64(rva-virtualAddress)
		if fileOffset >= uint64(len(s.data)) {
			return 0, false
		}
		return int(fileOffset), true
	}
	return 0, false
}

func (s sectionTable) findResource(base, directory int, ids []uint32) ([]byte, error) {
	if len(ids) == 0 || directory < base || directory+16 > len(s.data) {
		return nil, errors.New("invalid PE resource directory")
	}
	named, ok := u16(s.data, directory+12)
	if !ok {
		return nil, errors.New("invalid PE resource entry count")
	}
	idCount, ok := u16(s.data, directory+14)
	if !ok {
		return nil, errors.New("invalid PE resource ID count")
	}
	entryStart := directory + 16 + int(named)*8
	entryEnd := entryStart + int(idCount)*8
	if entryStart < directory || entryEnd < entryStart || entryEnd > len(s.data) {
		return nil, errors.New("truncated PE resource entries")
	}
	for entry := entryStart; entry < entryEnd; entry += 8 {
		name, ok := u32(s.data, entry)
		if !ok || name&0x80000000 != 0 || name&0x7fffffff != ids[0] {
			continue
		}
		offset, ok := u32(s.data, entry+4)
		if !ok {
			return nil, errors.New("invalid PE resource child offset")
		}
		if len(ids) > 1 {
			if offset&0x80000000 == 0 {
				return nil, errors.New("PE manifest resource tree ended early")
			}
			return s.findResource(base, base+int(offset&0x7fffffff), ids[1:])
		}
		if offset&0x80000000 != 0 {
			return nil, errors.New("PE manifest resource has no data entry")
		}
		dataEntry := base + int(offset&0x7fffffff)
		if dataEntry < base || dataEntry+16 > len(s.data) {
			return nil, errors.New("truncated PE manifest data entry")
		}
		resourceRVA, ok := u32(s.data, dataEntry)
		if !ok {
			return nil, errors.New("invalid PE manifest data RVA")
		}
		resourceSize, ok := u32(s.data, dataEntry+4)
		if !ok || resourceSize == 0 {
			return nil, errors.New("empty PE manifest resource")
		}
		resourceOffset, ok := s.fileOffset(resourceRVA)
		if !ok || uint64(resourceOffset)+uint64(resourceSize) > uint64(len(s.data)) {
			return nil, errors.New("PE manifest resource is outside its sections")
		}
		return s.data[resourceOffset : resourceOffset+int(resourceSize)], nil
	}
	return nil, errors.New("PE does not contain RT_MANIFEST resource ID 1")
}

func decodeUTF16(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, errors.New("manifest resource is neither UTF-8 nor UTF-16")
	}
	words := make([]uint16, len(data)/2)
	for index := range words {
		words[index] = binary.LittleEndian.Uint16(data[index*2:])
	}
	if len(words) > 0 && words[0] == 0xfeff {
		words = words[1:]
	}
	decoded := string(utf16.Decode(words))
	return []byte(strings.TrimRight(decoded, "\x00")), nil
}

func u16(data []byte, offset int) (uint16, bool) {
	if offset < 0 || offset+2 > len(data) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(data[offset:]), true
}

func u32(data []byte, offset int) (uint32, bool) {
	if offset < 0 || offset+4 > len(data) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[offset:]), true
}

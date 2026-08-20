package binarytarget

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
)

var ErrInvalid = errors.New("executable target does not match the declared platform")

func Validate(path, platform, architecture string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrInvalid
	}
	defer file.Close()
	header := make([]byte, 32)
	if _, err := io.ReadFull(file, header); err != nil {
		return ErrInvalid
	}
	switch platform {
	case "linux":
		if string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 {
			return ErrInvalid
		}
		machine := binary.LittleEndian.Uint16(header[18:20])
		if architecture == "amd64" && machine == 62 || architecture == "arm64" && machine == 183 {
			return nil
		}
	case "darwin":
		if binary.LittleEndian.Uint32(header[:4]) != 0xfeedfacf {
			return ErrInvalid
		}
		cpu := binary.LittleEndian.Uint32(header[4:8])
		if architecture == "amd64" && cpu == 0x01000007 || architecture == "arm64" && cpu == 0x0100000c {
			return nil
		}
	case "windows":
		return validatePE(file, architecture)
	}
	return ErrInvalid
}

func validatePE(file *os.File, architecture string) error {
	dos := make([]byte, 64)
	if _, err := file.ReadAt(dos, 0); err != nil || string(dos[:2]) != "MZ" {
		return ErrInvalid
	}
	offset := int64(binary.LittleEndian.Uint32(dos[0x3c:0x40]))
	if offset < 64 || offset > 16<<20 {
		return ErrInvalid
	}
	coff := make([]byte, 24)
	if _, err := file.ReadAt(coff, offset); err != nil || string(coff[:4]) != "PE\x00\x00" {
		return ErrInvalid
	}
	machine := binary.LittleEndian.Uint16(coff[4:6])
	optionalSize := binary.LittleEndian.Uint16(coff[20:22])
	if optionalSize < 2 {
		return ErrInvalid
	}
	magic := make([]byte, 2)
	if _, err := file.ReadAt(magic, offset+24); err != nil || binary.LittleEndian.Uint16(magic) != 0x20b {
		return ErrInvalid
	}
	if architecture == "amd64" && machine == 0x8664 || architecture == "arm64" && machine == 0xaa64 {
		return nil
	}
	return ErrInvalid
}

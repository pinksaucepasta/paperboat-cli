package binarytarget

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExecutableTargets(t *testing.T) {
	root := t.TempDir()
	write := func(name string, body []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	elf := make([]byte, 32)
	copy(elf, "\x7fELF")
	elf[4], elf[5] = 2, 1
	binary.LittleEndian.PutUint16(elf[18:20], 62)
	macho := make([]byte, 32)
	binary.LittleEndian.PutUint32(macho[:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(macho[4:8], 0x0100000c)
	pe := make([]byte, 256)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:0x40], 128)
	copy(pe[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[132:134], 0x8664)
	binary.LittleEndian.PutUint16(pe[148:150], 0xf0)
	binary.LittleEndian.PutUint16(pe[152:154], 0x20b)
	linux, darwin, windows := write("linux", elf), write("darwin", macho), write("windows.exe", pe)
	if err := Validate(linux, "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(darwin, "darwin", "arm64"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(windows, "windows", "amd64"); err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]struct{ path, platform, architecture string }{
		"wrong platform":        {linux, "darwin", "amd64"},
		"wrong architecture":    {darwin, "darwin", "amd64"},
		"wrong pe architecture": {windows, "windows", "arm64"},
		"wrong pe format":       {linux, "windows", "amd64"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(input.path, input.platform, input.architecture); err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
}

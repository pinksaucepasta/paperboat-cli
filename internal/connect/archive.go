package connect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractTarGz(contents []byte, destination string) error {
	gz, err := gzip.NewReader(bytes.NewReader(contents))
	if err != nil {
		return ErrInstallationFailed
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ErrInstallationFailed
		}
		name := filepath.Clean(header.Name)
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return ErrInstallationFailed
		}
		path := filepath.Join(destination, name)
		if path != destination && !strings.HasPrefix(path, destination+string(filepath.Separator)) {
			return ErrInstallationFailed
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, os.FileMode(header.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(file, tr)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return ErrInstallationFailed
			}
		default:
			return ErrInstallationFailed
		}
	}
}

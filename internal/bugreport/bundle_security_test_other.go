//go:build !windows

package bugreport

import "os"

func writeTestBundle(path string, content []byte) error {
	return os.WriteFile(path, content, 0o600)
}

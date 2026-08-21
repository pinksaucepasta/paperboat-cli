//go:build !windows

package enrollment

import "os"

func makeEnrollmentConfigPrivate(path string) error { return os.Chmod(path, 0o600) }

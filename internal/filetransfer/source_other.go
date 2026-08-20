//go:build !windows

package filetransfer

import "os"

func openSourceFile(path string) (*os.File, error) { return os.Open(path) }

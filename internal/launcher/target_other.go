//go:build !windows

package launcher

func resolveTargetPath(path string) (string, error) { return path, nil }

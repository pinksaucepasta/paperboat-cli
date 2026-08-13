//go:build linux

package inbox

import "github.com/pinksaucepasta/paperboat/internal/userpaths"

func DownloadsDir() (string, error) { return userpaths.Downloads() }

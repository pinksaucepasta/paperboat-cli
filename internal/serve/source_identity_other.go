//go:build !darwin && !linux

package serve

import (
	"fmt"
	"os"
)

func sourceIdentity(info os.FileInfo) string {
	return fmt.Sprintf("portable:%d:%d:%d", info.Size(), info.ModTime().UnixNano(), uint32(info.Mode()))
}

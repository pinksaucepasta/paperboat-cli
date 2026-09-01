//go:build darwin || linux

package hostruntimecmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// RepairManagedHost asks the fixed installed runtime binary to recover its
// persisted lifecycle transaction and re-apply the exact prior declaration.
// No caller-controlled installation payload crosses the elevation boundary.
func RepairManagedHost(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "--", "/usr/bin/env",
		"PAPERBOAT_INVOKING_UID="+strconv.Itoa(os.Getuid()), systemWorkerExecutable(), "__runtime-service", "repair-persisted")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("administrator approval or host service repair failed: %w: %s", err, stderr.String())
	}
	return nil
}

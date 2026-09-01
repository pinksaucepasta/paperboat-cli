//go:build !darwin && !linux && !windows

package hostruntimecmd

import (
	"context"
	"errors"
)

func RepairManagedHost(context.Context) error {
	return errors.New("managed Paperboat host repair is unsupported on this platform")
}

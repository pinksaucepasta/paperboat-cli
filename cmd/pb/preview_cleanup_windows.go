//go:build windows

package main

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntimeentry"
)

func cleanupDurablePreviewServicesWindows(ctx context.Context, roots []string) error {
	if len(roots) == 0 {
		return nil
	}
	var result error
	for _, root := range roots {
		result = errors.Join(result, hostruntimeentry.RemoveAllPreviewServices(ctx, root))
	}
	return result
}

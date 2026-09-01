//go:build !windows

package releaseeligibility

import "testing"

func requireUsableStoreTestPath(*testing.T, FileStore) {}

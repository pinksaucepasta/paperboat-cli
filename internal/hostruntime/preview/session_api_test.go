package preview

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

func TestLeaseFromAPIPreservesETagGeneration(t *testing.T) {
	value := api.PreviewLease{ID: "prv_generation_1", ETag: formatLeaseETag("prv_generation_1", 7)}
	lease := leaseFromAPI(value)
	if lease.Generation != 7 || lease.ETag != value.ETag {
		t.Fatalf("lease generation=%d etag=%q", lease.Generation, lease.ETag)
	}
}

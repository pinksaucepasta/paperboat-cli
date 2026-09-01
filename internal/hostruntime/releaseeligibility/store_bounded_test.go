package releaseeligibility

import (
	"context"
	"errors"
	"io"
	"testing"
)

// repeatingReader exposes a large logical input while returning only the
// caller's buffer size on each read. The test therefore exercises the same
// bounded path a sparse or hostile record would take without allocating the
// logical input itself.
type repeatingReader struct {
	remaining int64
}

func (r *repeatingReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	read := int64(len(buffer))
	if read > r.remaining {
		read = r.remaining
	}
	for index := 0; index < int(read); index++ {
		buffer[index] = 'x'
	}
	r.remaining -= read
	return int(read), nil
}

func TestReadBoundedRejectsLogicalOversizeWithoutAllocatingIt(t *testing.T) {
	reader := &repeatingReader{remaining: MaxDeferralBytes + 1}
	body, err := readBounded(context.Background(), reader, MaxDeferralBytes)
	if !errors.Is(err, ErrRecordTooLarge) || body != nil {
		t.Fatalf("body=%d err=%v, want no body and ErrRecordTooLarge", len(body), err)
	}
}

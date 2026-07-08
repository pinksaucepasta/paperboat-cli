package upload

import (
	"context"
	"errors"
)

var ErrUnavailable = errors.New("papercode image upload endpoint is not configured")

// DisabledUploader fails every upload so the paste interceptor preserves the
// original local path instead of rewriting to a fake VM path in real sessions.
type DisabledUploader struct{}

func NewDisabledUploader() *DisabledUploader { return &DisabledUploader{} }

func (u *DisabledUploader) Upload(_ context.Context, _ Image) (string, error) {
	return "", ErrUnavailable
}

var _ Uploader = (*DisabledUploader)(nil)

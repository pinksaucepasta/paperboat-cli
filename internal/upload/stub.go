package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path"
)

// StubUploader stands in for the papercode-server upload endpoint. It does not
// transfer anything; it deterministically derives a plausible VM-side path from
// the image content so the paste bridge can be exercised end-to-end locally.
// The real Uploader (T3 WebSocket transport) drops in behind the Uploader
// interface with no changes to the paste pipeline.
type StubUploader struct {
	// BaseDir is the VM directory returned paths live under. Config-driven.
	BaseDir string
}

// NewStubUploader returns a stub writing to the conventional papercode
// attachments dir on the VM.
func NewStubUploader(baseDir string) *StubUploader {
	if baseDir == "" {
		baseDir = "/workspace/.paperboat/attachments"
	}
	return &StubUploader{BaseDir: baseDir}
}

// Upload implements Uploader by returning a content-addressed VM path.
func (u *StubUploader) Upload(_ context.Context, img Image) (string, error) {
	sum := sha256.Sum256(img.Bytes)
	name := hex.EncodeToString(sum[:8]) + ext(img)
	return path.Join(u.BaseDir, name), nil
}

func ext(img Image) string {
	for e, m := range imageMimeByExt {
		if m == img.MimeType {
			return e
		}
	}
	return ""
}

// Package upload bridges a local pasted image to a VM-side path. The wrapper
// reads the local file, hands it to an Uploader, and rewrites the paste to the
// returned VM path so the remote agent receives something it can open.
//
// Images are staged through papercode's authenticated multipart HTTP contract.
// The interface keeps transport details swappable and paperboat-cli out of
// papercode's implementation.
package upload

import (
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

// Image is a prepared, in-memory image ready to upload.
type Image struct {
	Name     string
	MimeType string
	Bytes    []byte
	// DataURL is retained for callers that prepare images for older integrations;
	// staged-image HTTP uploads send Bytes as a multipart stream.
	DataURL string
}

// Limits captures the papercode-compatible upload constraints. They come from
// config so they stay tunable and in sync with the server.
type Limits struct {
	MaxImageBytes       int64
	MaxDataURLChars     int
	MaxAttachments      int
	AllowedMimePrefixes []string
	AllowedMIMETypes    []string
}

// Uploader sends a prepared image and returns its VM-side path.
type Uploader interface {
	// Upload transfers img and returns the absolute path on the VM where the
	// agent can read it.
	Upload(ctx context.Context, img Image) (vmPath string, err error)
}

// PrepareImage reads a local file, infers its MIME type, enforces limits, and
// prepares raw bytes for the streaming multipart uploader. It returns an error
// if the file is not an allowed image or exceeds a limit — callers fail open
// (keep the original paste text).
func PrepareImage(path string, limits Limits) (Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return Image{}, fmt.Errorf("open image: %w", err)
	}
	defer f.Close()
	return PrepareImageFile(f, path, limits)
}

// PrepareImageFile validates and reads an already-open image descriptor. The
// caller retains ownership of f. This binds path authorization and uploaded
// bytes to the same file even if the pathname changes concurrently.
func PrepareImageFile(f *os.File, displayPath string, limits Limits) (Image, error) {
	info, err := f.Stat()
	if err != nil {
		return Image{}, fmt.Errorf("stat image: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Image{}, fmt.Errorf("%s is not a regular image file", displayPath)
	}
	if limits.MaxImageBytes > 0 && info.Size() > limits.MaxImageBytes {
		return Image{}, fmt.Errorf("image %s is %d bytes, over limit %d", displayPath, info.Size(), limits.MaxImageBytes)
	}

	mimeType := MimeTypeFor(displayPath)
	if !mimeAllowedByPolicy(mimeType, limits.AllowedMimePrefixes, limits.AllowedMIMETypes) {
		return Image{}, fmt.Errorf("%s has type %q which is not an allowed image", displayPath, mimeType)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Image{}, fmt.Errorf("seek image: %w", err)
	}

	// Read through the already-open descriptor so a path replacement after the
	// validation above cannot cause us to upload a different file. The extra
	// byte makes the post-read limit check allocation-bounded.
	var reader io.Reader = f
	if limits.MaxImageBytes > 0 {
		reader = io.LimitReader(f, limits.MaxImageBytes+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return Image{}, fmt.Errorf("read image: %w", err)
	}
	if limits.MaxImageBytes > 0 && int64(len(data)) > limits.MaxImageBytes {
		return Image{}, fmt.Errorf("image %s is %d bytes, over limit %d", displayPath, len(data), limits.MaxImageBytes)
	}

	return Image{
		Name:     filepath.Base(displayPath),
		MimeType: mimeType,
		Bytes:    data,
	}, nil
}

// MimeTypeFor infers an image MIME type from the file extension, matching the
// extensions papercode's attachmentStore accepts.
func MimeTypeFor(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if t, ok := imageMimeByExt[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return strings.SplitN(t, ";", 2)[0]
	}
	return "application/octet-stream"
}

// imageMimeByExt covers the safe image extensions papercode allows
// (apps/server/src/attachmentStore.ts) so behavior stays consistent.
var imageMimeByExt = map[string]string{
	".avif": "image/avif",
	".bmp":  "image/bmp",
	".gif":  "image/gif",
	".heic": "image/heic",
	".heif": "image/heif",
	".ico":  "image/x-icon",
	".jpeg": "image/jpeg",
	".jpg":  "image/jpeg",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".webp": "image/webp",
}

// IsImagePath reports whether path has a recognized image extension. Used by the
// paste detector before touching the filesystem.
func IsImagePath(path string) bool {
	_, ok := imageMimeByExt[strings.ToLower(filepath.Ext(path))]
	return ok
}

func mimeAllowed(mimeType string, prefixes []string) bool {
	return mimeAllowedByPolicy(mimeType, prefixes, nil)
}

func mimeAllowedByPolicy(mimeType string, prefixes, exact []string) bool {
	for _, allowed := range exact {
		if strings.EqualFold(mimeType, allowed) {
			return true
		}
	}
	if len(exact) > 0 {
		return false
	}
	if len(prefixes) == 0 {
		prefixes = []string{"image/"}
	}
	for _, p := range prefixes {
		if strings.HasPrefix(mimeType, p) {
			return true
		}
	}
	return false
}

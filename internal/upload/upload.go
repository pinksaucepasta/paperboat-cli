// Package upload bridges a local pasted image to a VM-side path. The wrapper
// reads the local file, hands it to an Uploader, and rewrites the paste to the
// returned VM path so the remote agent receives something it can open.
//
// Images are staged through Paperboat's authenticated multipart HTTP contract.
// The interface keeps transport details swappable and paperboat-cli out of
// Paperboat's implementation.
package upload

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

// Image is a prepared, seekable image descriptor ready to upload.
type Image struct {
	Name     string
	MimeType string
	Size     int64
	SHA256   [sha256.Size]byte
	Reader   io.ReadSeeker
	close    io.Closer
}

// Close releases an image opened by PrepareImage. Images prepared from a
// caller-owned descriptor do not take ownership of that descriptor.
func (i Image) Close() error {
	if i.close == nil {
		return nil
	}
	return i.close.Close()
}

// Limits captures the Paperboat-compatible upload constraints. They come from
// config so they stay tunable and in sync with the server.
type Limits struct {
	MaxImageBytes       int64
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

// PrepareImage opens a local file, infers its MIME type, enforces limits, and
// prepares a descriptor for the streaming multipart uploader. It returns an error
// if the file is not an allowed image or exceeds a limit — callers fail open
// (keep the original paste text).
func PrepareImage(path string, limits Limits) (Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return Image{}, fmt.Errorf("open image: %w", err)
	}
	image, err := PrepareImageFile(f, path, limits)
	if err != nil {
		_ = f.Close()
		return Image{}, err
	}
	image.close = f
	return image, nil
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

	// Hash through the already-open descriptor so a path replacement after the
	// validation above cannot change the selected file. The upload later rewinds
	// and streams this same descriptor without retaining a second in-memory copy.
	var reader io.Reader = f
	if limits.MaxImageBytes > 0 {
		reader = io.LimitReader(f, limits.MaxImageBytes+1)
	}
	hash := sha256.New()
	read, err := io.CopyBuffer(hash, reader, make([]byte, 32<<10))
	if err != nil {
		return Image{}, fmt.Errorf("hash image: %w", err)
	}
	if limits.MaxImageBytes > 0 && read > limits.MaxImageBytes {
		return Image{}, fmt.Errorf("image %s is %d bytes, over limit %d", displayPath, read, limits.MaxImageBytes)
	}
	if read != info.Size() {
		return Image{}, fmt.Errorf("image %s changed while it was being prepared", displayPath)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Image{}, fmt.Errorf("rewind image: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))

	return Image{
		Name:     filepath.Base(displayPath),
		MimeType: mimeType,
		Size:     read,
		SHA256:   digest,
		Reader:   f,
	}, nil
}

// MimeTypeFor infers an image MIME type from the file extension, matching the
// extensions Paperboat's attachmentStore accepts.
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

// imageMimeByExt covers the safe image extensions Paperboat allows
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

func mimeAllowedByPolicy(mimeType string, prefixes, exact []string) bool {
	for _, allowed := range exact {
		if strings.EqualFold(strings.TrimSpace(allowed), "image/*") && strings.HasPrefix(strings.ToLower(mimeType), "image/") {
			return true
		}
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

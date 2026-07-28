package upload

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name string, n int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseLimits() Limits {
	return Limits{
		MaxImageBytes:       10 << 20,
		MaxAttachments:      8,
		AllowedMimePrefixes: []string{"image/"},
	}
}

func TestPrepareImageReturnsSeekableDescriptorAndDigest(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.png", 4)
	img, err := PrepareImage(p, baseLimits())
	if err != nil {
		t.Fatal(err)
	}
	if img.MimeType != "image/png" {
		t.Fatalf("mime=%q", img.MimeType)
	}
	defer img.Close()
	if img.Size != 4 || img.Reader == nil {
		t.Fatalf("size=%d reader=%T", img.Size, img.Reader)
	}
	if img.Name != "x.png" {
		t.Fatalf("name=%q", img.Name)
	}
	want := sha256.Sum256(make([]byte, 4))
	if img.SHA256 != want {
		t.Fatalf("digest=%x want=%x", img.SHA256, want)
	}
	data, err := io.ReadAll(img.Reader)
	if err != nil || len(data) != 4 {
		t.Fatalf("streamed bytes=%d err=%v", len(data), err)
	}
}

func TestPrepareImageRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "big.png", 32)
	lim := baseLimits()
	lim.MaxImageBytes = 16
	if _, err := PrepareImage(p, lim); err == nil {
		t.Fatal("expected size error")
	}
}

func TestPrepareImageRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := PrepareImage(filepath.Join(dir, "fake.png"), baseLimits()); err == nil {
		t.Fatal("expected missing-file error")
	}
	if _, err := PrepareImage(dir, baseLimits()); err == nil || !strings.Contains(err.Error(), "not a regular image file") {
		t.Fatalf("expected non-regular-file error, got %v", err)
	}
}

func TestPrepareImageHonorsExactAllowedMIMETypes(t *testing.T) {
	dir := t.TempDir()
	png := write(t, dir, "image.png", 3)
	jpg := write(t, dir, "image.jpg", 3)

	if _, err := PrepareImage(png, Limits{AllowedMIMETypes: []string{"image/png"}}); err != nil {
		t.Fatalf("png should be allowed: %v", err)
	}
	if _, err := PrepareImage(jpg, Limits{AllowedMIMETypes: []string{"image/png"}}); err == nil {
		t.Fatal("jpg should be rejected by exact MIME policy")
	}
}

func TestPrepareImageAllowsAdvertisedTIFF(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "clipboard.tiff", 4)
	if _, err := PrepareImage(path, Limits{AllowedMIMETypes: []string{"image/tiff"}}); err != nil {
		t.Fatalf("TIFF should be allowed: %v", err)
	}
}

func TestPrepareImageHonorsImageWildcard(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "photo.avif", 4)
	if _, err := PrepareImage(path, Limits{AllowedMIMETypes: []string{"image/*"}}); err != nil {
		t.Fatalf("image wildcard should allow AVIF: %v", err)
	}
}

func TestPrepareImageRejectsNonImage(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "notes.txt", 10)
	if _, err := PrepareImage(p, baseLimits()); err == nil {
		t.Fatal("expected non-image rejection")
	}
}

func TestIsImagePath(t *testing.T) {
	cases := map[string]bool{
		"a.png": true, "b.JPG": true, "c.webp": true, "d.txt": false, "e": false,
	}
	for in, want := range cases {
		if got := IsImagePath(in); got != want {
			t.Errorf("IsImagePath(%q)=%v want %v", in, got, want)
		}
	}
}

package upload

import (
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
		MaxDataURLChars:     14_000_000,
		MaxAttachments:      8,
		AllowedMimePrefixes: []string{"image/"},
	}
}

func TestPrepareImageReturnsRawBytes(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.png", 4)
	img, err := PrepareImage(p, baseLimits())
	if err != nil {
		t.Fatal(err)
	}
	if img.MimeType != "image/png" {
		t.Fatalf("mime=%q", img.MimeType)
	}
	if len(img.Bytes) != 4 || img.DataURL != "" {
		t.Fatalf("payload bytes=%d dataurl=%q", len(img.Bytes), img.DataURL)
	}
	if img.Name != "x.png" {
		t.Fatalf("name=%q", img.Name)
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

func TestPrepareImageIgnoresLegacyDataURLLimit(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "m.png", 1000)
	lim := baseLimits()
	lim.MaxDataURLChars = 100
	if _, err := PrepareImage(p, lim); err != nil {
		t.Fatalf("raw multipart upload should ignore legacy data URL limit: %v", err)
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

func TestStubUploaderDeterministic(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "x.png", 8)
	img, err := PrepareImage(p, baseLimits())
	if err != nil {
		t.Fatal(err)
	}
	u := NewStubUploader("")
	a, err := u.Upload(t.Context(), img)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := u.Upload(t.Context(), img)
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if !strings.HasSuffix(a, ".png") {
		t.Fatalf("expected .png suffix, got %q", a)
	}
}

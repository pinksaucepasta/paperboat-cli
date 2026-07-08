package upload

import (
	"context"
	"errors"
	"testing"
)

func TestDisabledUploaderFails(t *testing.T) {
	_, err := NewDisabledUploader().Upload(context.Background(), Image{Name: "image.png"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

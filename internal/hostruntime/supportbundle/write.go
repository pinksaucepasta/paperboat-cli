package supportbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
)

const temporaryCreateAttempts = 16

func (b *Builder) Write(ctx context.Context, preview Preview, outputPath string) (WriteResult, error) {
	if b == nil {
		return WriteResult{}, &Error{Code: ErrorInvalidPreview, Operation: "write support bundle"}
	}
	if ctx == nil {
		return WriteResult{}, contextError("write support bundle", context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return WriteResult{}, contextError("write support bundle", err)
	}
	digest := sha256.Sum256(preview.body)
	actualDigest := hex.EncodeToString(digest[:])
	manifestBody, manifestErr := json.Marshal(preview.Manifest)
	manifestDigest := sha256.Sum256(manifestBody)
	if len(preview.body) == 0 || actualDigest != preview.digest || int64(len(preview.body)) > b.limits.MaxTotalBytes ||
		manifestErr != nil || hex.EncodeToString(manifestDigest[:]) != preview.manifestDigest ||
		preview.Manifest.SchemaVersion != SchemaVersion || preview.Manifest.Format != FormatVersion {
		return WriteResult{}, &Error{Code: ErrorInvalidPreview, Operation: "write support bundle"}
	}
	if err := b.validatePreview(preview); err != nil {
		return WriteResult{}, err
	}
	if err := validateOutputPath(outputPath); err != nil {
		return WriteResult{}, err
	}
	if err := b.writeAtomic(ctx, outputPath, preview.body); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{
		Path:      outputPath,
		SizeBytes: int64(len(preview.body)),
		SHA256:    actualDigest,
		Manifest:  preview.Manifest,
	}, nil
}

func (b *Builder) validatePreview(preview Preview) error {
	if b == nil {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
	}
	wantLimits := ManifestLimits{
		MaxItems:                  b.limits.MaxItems,
		MaxItemBytes:              b.limits.MaxItemBytes,
		MaxTotalBytes:             b.limits.MaxTotalBytes,
		PerCollectorTimeoutMillis: b.limits.PerCollectorTimeout.Milliseconds(),
		TotalTimeoutMillis:        b.limits.TotalTimeout.Milliseconds(),
	}
	if preview.Manifest.Limits != wantLimits || len(preview.Manifest.Items) > b.limits.MaxItems || preview.Manifest.ContentBytes < 0 || preview.Manifest.ContentBytes > b.limits.MaxTotalBytes {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
	}
	manifestBytes, err := json.Marshal(preview.Manifest)
	if err != nil {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview", Cause: err}
	}
	var document bundleDocument
	if err := json.Unmarshal(preview.body, &document); err != nil || document.SchemaVersion != SchemaVersion {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview", Cause: err}
	}
	documentManifest, err := json.Marshal(document.Manifest)
	if err != nil || string(documentManifest) != string(manifestBytes) {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview", Cause: err}
	}
	if len(document.Items) != len(preview.Manifest.Items) {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
	}
	collectorNames := make([]string, 0, len(preview.Manifest.Collectors))
	collectorCounts := make(map[string]int, len(preview.Manifest.Collectors))
	for index, collector := range preview.Manifest.Collectors {
		if collector.Name == "" || !collectorNamePattern.MatchString(collector.Name) || (index > 0 && preview.Manifest.Collectors[index-1].Name >= collector.Name) || collector.Result != ResultOK && collector.Result != ResultError && collector.Result != ResultRedacted || collector.ItemCount < 0 {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		if _, exists := collectorCounts[collector.Name]; exists {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		collectorNames = append(collectorNames, collector.Name)
		collectorCounts[collector.Name] = collector.ItemCount
		if collector.Result == ResultError && collector.ItemCount != 0 {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
	}
	if !sort.StringsAreSorted(collectorNames) {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
	}
	seenPaths := make([]string, 0, len(preview.Manifest.Items))
	counts := make(map[string]int, len(collectorCounts))
	var contentBytes int64
	for index, item := range preview.Manifest.Items {
		if err := validateLogicalPath(item.Path); err != nil || (index > 0 && preview.Manifest.Items[index-1].Path >= item.Path) || item.Collector == "" || !collectorNamePattern.MatchString(item.Collector) || item.Result != ResultOK && item.Result != ResultRedacted || item.SizeBytes < 0 || item.SizeBytes > b.limits.MaxItemBytes || item.Redactions < 0 || len(item.SHA256) != sha256.Size*2 {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		if _, exists := collectorCounts[item.Collector]; !exists {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		if conflict := pathConflict(item.Path, seenPaths); conflict != "" {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		seenPaths = append(seenPaths, item.Path)
		counts[item.Collector]++
		contentBytes += item.SizeBytes
		if contentBytes < 0 || contentBytes > b.limits.MaxTotalBytes {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
	}
	if contentBytes != preview.Manifest.ContentBytes || len(document.Items) != len(seenPaths) {
		return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
	}
	for collector, want := range collectorCounts {
		if counts[collector] != want {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
	}
	for index, item := range document.Items {
		manifestItem := preview.Manifest.Items[index]
		if item.Path != manifestItem.Path || item.Kind != manifestItem.Kind || item.Path == "" {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		canonical, err := canonicalDocumentItem(item)
		if err != nil {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview", Cause: err}
		}
		if int64(len(canonical)) != manifestItem.SizeBytes {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
		digest := sha256.Sum256(canonical)
		if hex.EncodeToString(digest[:]) != manifestItem.SHA256 {
			return &Error{Code: ErrorInvalidPreview, Operation: "validate support bundle preview"}
		}
	}
	return nil
}

func canonicalDocumentItem(item bundleItem) ([]byte, error) {
	switch item.Kind {
	case ItemKindText:
		if item.Text == nil || item.Metadata != nil {
			return nil, errors.New("invalid text item")
		}
		return []byte(*item.Text), nil
	case ItemKindMetadata:
		if item.Text != nil {
			return nil, errors.New("invalid metadata item")
		}
		if item.Metadata == nil {
			return []byte("{}"), nil
		}
		return json.Marshal(item.Metadata)
	default:
		return nil, errors.New("invalid item kind")
	}
}

// ValidateOutputPath verifies that outputPath is an absolute, clean, new
// regular-file destination under an existing directory tree containing no
// symbolic links or platform reparse points.
func ValidateOutputPath(outputPath string) error {
	if outputPath == "" || len(outputPath) > 4096 || !filepath.IsAbs(outputPath) || unsafeOutputPathCharacters(outputPath) || filepath.Clean(outputPath) != outputPath || filepath.Base(outputPath) == "." {
		return &Error{Code: ErrorInvalidOutput, Operation: "write support bundle"}
	}
	return validatePlatformOutputPath(outputPath)
}

func unsafeOutputPathCharacters(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func validateOutputPath(outputPath string) error { return ValidateOutputPath(outputPath) }

func writeContext(ctx context.Context, writer io.Writer, body []byte) error {
	const chunkSize = 32 << 10
	for len(body) > 0 {
		if err := ctx.Err(); err != nil {
			return contextError("write support bundle", err)
		}
		chunk := body
		if len(chunk) > chunkSize {
			chunk = chunk[:chunkSize]
		}
		written, err := writer.Write(chunk)
		if err != nil {
			return &Error{Code: ErrorWriteFailed, Operation: "write support bundle output", Cause: err}
		}
		if written <= 0 || written > len(chunk) {
			return &Error{Code: ErrorWriteFailed, Operation: "write support bundle output", Cause: io.ErrShortWrite}
		}
		body = body[written:]
	}
	return nil
}

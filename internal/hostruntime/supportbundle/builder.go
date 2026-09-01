package supportbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	hardMaxCollectors = 64
	hardMaxItems      = 256
	hardMaxItemBytes  = 4 << 20
	hardMaxTotalBytes = 16 << 20
	hardMaxTimeout    = time.Minute
)

var (
	collectorNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	pathSegmentPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)
	allowedPathRoots     = map[string]struct{}{
		"diagnostics": {},
		"events":      {},
		"health":      {},
		"logs":        {},
		"metrics":     {},
		"state":       {},
		"system":      {},
	}
)

type Builder struct {
	limits        Limits
	collectors    []namedCollector
	beforePublish func(string) error
	syncParent    func(string) error
}

type namedCollector struct {
	name      string
	collector Collector
}

func New(config Config, collectors ...Collector) (*Builder, error) {
	limits := config.Limits
	applyLimitDefaults(&limits)
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	if len(collectors) > hardMaxCollectors {
		return nil, &Error{Code: ErrorCollectorLimitExceeded, Operation: "configure support bundle"}
	}

	ordered := make([]namedCollector, 0, len(collectors))
	for _, collector := range collectors {
		name, ok := safeCollectorName(collector)
		if !ok || !collectorNamePattern.MatchString(name) {
			return nil, &Error{Code: ErrorInvalidCollector, Operation: "configure support bundle"}
		}
		ordered = append(ordered, namedCollector{name: name, collector: collector})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].name == ordered[i].name {
			return nil, &Error{Code: ErrorDuplicateCollector, Operation: "configure support bundle"}
		}
	}
	return &Builder{limits: limits, collectors: ordered}, nil
}

func applyLimitDefaults(limits *Limits) {
	defaults := Defaults()
	if limits.MaxItems == 0 {
		limits.MaxItems = defaults.MaxItems
	}
	if limits.MaxItemBytes == 0 {
		limits.MaxItemBytes = defaults.MaxItemBytes
	}
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if limits.PerCollectorTimeout == 0 {
		limits.PerCollectorTimeout = defaults.PerCollectorTimeout
	}
	if limits.TotalTimeout == 0 {
		limits.TotalTimeout = defaults.TotalTimeout
	}
}

func validateLimits(limits Limits) error {
	if limits.MaxItems < 1 || limits.MaxItems > hardMaxItems ||
		limits.MaxItemBytes < 1 || limits.MaxItemBytes > hardMaxItemBytes ||
		limits.MaxTotalBytes < 1 || limits.MaxTotalBytes > hardMaxTotalBytes ||
		limits.PerCollectorTimeout < time.Millisecond || limits.PerCollectorTimeout > hardMaxTimeout ||
		limits.TotalTimeout < time.Millisecond || limits.TotalTimeout > hardMaxTimeout {
		return &Error{Code: ErrorInvalidLimits, Operation: "configure support bundle"}
	}
	return nil
}

type bundleDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Manifest      Manifest     `json:"manifest"`
	Items         []bundleItem `json:"items"`
}

type bundleItem struct {
	Path     string            `json:"path"`
	Kind     ItemKind          `json:"kind"`
	Text     *string           `json:"text,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (b *Builder) Preview(ctx context.Context) (Preview, error) {
	if b == nil {
		return Preview{}, &Error{Code: ErrorInvalidLimits, Operation: "collect support bundle"}
	}
	if ctx == nil {
		return Preview{}, &Error{Code: ErrorCanceled, Operation: "collect support bundle", Cause: context.Canceled}
	}
	totalCtx, cancel := context.WithTimeout(ctx, b.limits.TotalTimeout)
	defer cancel()

	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Format:        FormatVersion,
		Limits: ManifestLimits{
			MaxItems:                  b.limits.MaxItems,
			MaxItemBytes:              b.limits.MaxItemBytes,
			MaxTotalBytes:             b.limits.MaxTotalBytes,
			PerCollectorTimeoutMillis: b.limits.PerCollectorTimeout.Milliseconds(),
			TotalTimeoutMillis:        b.limits.TotalTimeout.Milliseconds(),
		},
		Collectors: make([]CollectorResult, 0, len(b.collectors)),
		Items:      make([]ItemResult, 0),
	}
	items := make([]bundleItem, 0)
	seen := make([]string, 0)

	for _, collector := range b.collectors {
		if err := totalCtx.Err(); err != nil {
			return Preview{}, contextError("collect support bundle", err)
		}

		collectorCtx, collectorCancel := context.WithTimeout(totalCtx, b.limits.PerCollectorTimeout)
		collected, collectErr, panicked := collectSafely(collectorCtx, collector.collector)
		collectorContextErr := collectorCtx.Err()
		collectorCancel()

		if err := totalCtx.Err(); err != nil {
			return Preview{}, contextError("collect support bundle", err)
		}

		collectorResult := CollectorResult{Name: collector.name, Result: ResultOK}
		if panicked {
			collectorResult.Result = ResultError
			collectorResult.ErrorCode = ErrorCollectorPanicked
			collectorResult.ErrorMessage = "collector panicked"
			manifest.Collectors = append(manifest.Collectors, collectorResult)
			continue
		}
		if collectErr != nil || collectorContextErr != nil {
			collectorResult.Result = ResultError
			if errors.Is(collectorContextErr, context.DeadlineExceeded) || errors.Is(collectErr, context.DeadlineExceeded) {
				collectorResult.ErrorCode = ErrorDeadlineExceeded
				collectorResult.ErrorMessage = "collector deadline exceeded"
			} else if errors.Is(collectorContextErr, context.Canceled) || errors.Is(collectErr, context.Canceled) {
				collectorResult.ErrorCode = ErrorCanceled
				collectorResult.ErrorMessage = "collector canceled"
			} else {
				collectorResult.ErrorCode = ErrorCollectorFailed
				collectorResult.ErrorMessage = "collector failed"
			}
			manifest.Collectors = append(manifest.Collectors, collectorResult)
			continue
		}

		for _, collectedItem := range collected {
			if len(items) >= b.limits.MaxItems {
				return Preview{}, &Error{Code: ErrorItemLimitExceeded, Operation: "collect support bundle"}
			}
			if err := validateLogicalPath(collectedItem.Path); err != nil {
				return Preview{}, err
			}
			if conflictCode := pathConflict(collectedItem.Path, seen); conflictCode != "" {
				return Preview{}, &Error{Code: conflictCode, Operation: "collect support bundle"}
			}

			encodedItem, result, err := b.prepareItem(collector.name, collectedItem)
			if err != nil {
				return Preview{}, err
			}
			if manifest.ContentBytes+result.SizeBytes > b.limits.MaxTotalBytes {
				return Preview{}, &Error{Code: ErrorTotalSizeExceeded, Operation: "collect support bundle"}
			}
			manifest.ContentBytes += result.SizeBytes
			manifest.Redactions += result.Redactions
			manifest.Items = append(manifest.Items, result)
			items = append(items, encodedItem)
			seen = append(seen, collectedItem.Path)
			collectorResult.ItemCount++
		}
		manifest.Collectors = append(manifest.Collectors, collectorResult)
	}

	sort.Slice(manifest.Items, func(i, j int) bool { return manifest.Items[i].Path < manifest.Items[j].Path })
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	document := bundleDocument{SchemaVersion: SchemaVersion, Manifest: manifest, Items: items}
	body, err := json.Marshal(document)
	if err != nil {
		return Preview{}, &Error{Code: ErrorWriteFailed, Operation: "encode support bundle", Cause: err}
	}
	body = append(body, '\n')
	if int64(len(body)) > b.limits.MaxTotalBytes {
		return Preview{}, &Error{Code: ErrorTotalSizeExceeded, Operation: "encode support bundle"}
	}
	digest := sha256.Sum256(body)
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return Preview{}, &Error{Code: ErrorWriteFailed, Operation: "encode support bundle manifest", Cause: err}
	}
	manifestDigest := sha256.Sum256(manifestBody)
	return Preview{
		Manifest:       manifest,
		body:           body,
		digest:         hex.EncodeToString(digest[:]),
		manifestDigest: hex.EncodeToString(manifestDigest[:]),
	}, nil
}

func safeCollectorName(collector Collector) (name string, ok bool) {
	if collector == nil {
		return "", false
	}
	defer func() {
		if recover() != nil {
			name = ""
			ok = false
		}
	}()
	return collector.Name(), true
}

func collectSafely(ctx context.Context, collector Collector) (items []CollectedItem, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			items = nil
			err = nil
			panicked = true
		}
	}()
	items, err = collector.Collect(ctx)
	return items, err, false
}

func (b *Builder) prepareItem(collector string, item CollectedItem) (bundleItem, ItemResult, error) {
	encoded := bundleItem{Path: item.Path, Kind: item.Kind}
	result := ItemResult{Path: item.Path, Collector: collector, Kind: item.Kind, Result: ResultOK}
	var canonical []byte

	switch item.Kind {
	case ItemKindText:
		if item.Metadata != nil {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidMetadata, Operation: "collect support bundle"}
		}
		if int64(len(item.Data)) > b.limits.MaxItemBytes {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorItemTooLarge, Operation: "collect support bundle"}
		}
		if !utf8.Valid(item.Data) {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidUTF8, Operation: "collect support bundle"}
		}
		if looksBinary(item.Data) {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorBinaryContent, Operation: "collect support bundle"}
		}
		text, count := redactString(string(item.Data))
		canonical = []byte(text)
		encoded.Text = &text
		result.Redactions = count
	case ItemKindMetadata:
		if len(item.Data) != 0 || item.Metadata == nil {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidMetadata, Operation: "collect support bundle"}
		}
		metadata := make(map[string]string, len(item.Metadata))
		if len(item.Metadata) > hardMaxItems {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidMetadata, Operation: "collect support bundle"}
		}
		for key, value := range item.Metadata {
			if !utf8.ValidString(key) || !utf8.ValidString(value) || !pathSegmentPattern.MatchString(key) || looksBinary([]byte(value)) {
				return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidMetadata, Operation: "collect support bundle"}
			}
			if int64(len(value)) > b.limits.MaxItemBytes {
				return bundleItem{}, ItemResult{}, &Error{Code: ErrorItemTooLarge, Operation: "collect support bundle"}
			}
			redacted, count := redactString(value)
			if sensitiveMetadataKey.MatchString(key) && redacted != RedactedValue {
				redacted = RedactedValue
				count++
			}
			metadata[key] = redacted
			result.Redactions += count
		}
		var err error
		canonical, err = json.Marshal(metadata)
		if err != nil {
			return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidMetadata, Operation: "collect support bundle", Cause: err}
		}
		encoded.Metadata = metadata
	default:
		return bundleItem{}, ItemResult{}, &Error{Code: ErrorInvalidKind, Operation: "collect support bundle"}
	}

	if int64(len(canonical)) > b.limits.MaxItemBytes {
		return bundleItem{}, ItemResult{}, &Error{Code: ErrorItemTooLarge, Operation: "collect support bundle"}
	}
	digest := sha256.Sum256(canonical)
	result.SizeBytes = int64(len(canonical))
	result.SHA256 = hex.EncodeToString(digest[:])
	if result.Redactions > 0 {
		result.Result = ResultRedacted
	}
	return encoded, result, nil
}

func validateLogicalPath(value string) error {
	if value == "" || len(value) > 240 || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return &Error{Code: ErrorInvalidPath, Operation: "collect support bundle"}
	}
	segments := strings.Split(value, "/")
	if len(segments) < 2 {
		return &Error{Code: ErrorInvalidPath, Operation: "collect support bundle"}
	}
	if _, ok := allowedPathRoots[segments[0]]; !ok {
		return &Error{Code: ErrorInvalidPath, Operation: "collect support bundle"}
	}
	for _, segment := range segments {
		if !pathSegmentPattern.MatchString(segment) || segment == "." || segment == ".." {
			return &Error{Code: ErrorInvalidPath, Operation: "collect support bundle"}
		}
	}
	return nil
}

func pathConflict(candidate string, existing []string) ErrorCode {
	for _, value := range existing {
		if value == candidate {
			return ErrorDuplicatePath
		}
		if strings.HasPrefix(value, candidate+"/") || strings.HasPrefix(candidate, value+"/") {
			return ErrorPathConflict
		}
	}
	return ""
}

func looksBinary(value []byte) bool {
	for _, b := range value {
		if b == 0 || b == 0x7f || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
			return true
		}
	}
	return false
}

func contextError(operation string, err error) error {
	code := ErrorCanceled
	if errors.Is(err, context.DeadlineExceeded) {
		code = ErrorDeadlineExceeded
	}
	return &Error{Code: code, Operation: operation, Cause: err}
}

func errorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

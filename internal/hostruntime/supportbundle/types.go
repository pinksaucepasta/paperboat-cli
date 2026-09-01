// Package supportbundle constructs bounded, redacted Paperboat diagnostic bundles.
//
// The package deliberately has no collectors that read the filesystem and no upload or
// network behavior. Callers inject already scoped collectors, inspect Preview.Manifest,
// and explicitly decide whether to write the exact previewed bytes.
package supportbundle

import (
	"context"
	"fmt"
	"time"
)

const (
	SchemaVersion = "paperboat.support_bundle.v1"
	FormatVersion = "paperboat.support_bundle.json.v1"
)

const RedactedValue = "[REDACTED]"

type ItemKind string

const (
	ItemKindText     ItemKind = "text"
	ItemKindMetadata ItemKind = "metadata"
)

type ResultCode string

const (
	ResultOK       ResultCode = "ok"
	ResultRedacted ResultCode = "redacted"
	ResultError    ResultCode = "error"
)

type ErrorCode string

const (
	ErrorCanceled               ErrorCode = "canceled"
	ErrorDeadlineExceeded       ErrorCode = "deadline_exceeded"
	ErrorCollectorFailed        ErrorCode = "collector_failed"
	ErrorCollectorPanicked      ErrorCode = "collector_panicked"
	ErrorInvalidLimits          ErrorCode = "invalid_limits"
	ErrorCollectorLimitExceeded ErrorCode = "collector_limit_exceeded"
	ErrorInvalidCollector       ErrorCode = "invalid_collector"
	ErrorDuplicateCollector     ErrorCode = "duplicate_collector"
	ErrorInvalidPath            ErrorCode = "invalid_path"
	ErrorDuplicatePath          ErrorCode = "duplicate_path"
	ErrorPathConflict           ErrorCode = "path_conflict"
	ErrorInvalidKind            ErrorCode = "invalid_kind"
	ErrorInvalidUTF8            ErrorCode = "invalid_utf8"
	ErrorBinaryContent          ErrorCode = "binary_content"
	ErrorInvalidMetadata        ErrorCode = "invalid_metadata"
	ErrorItemTooLarge           ErrorCode = "item_too_large"
	ErrorItemLimitExceeded      ErrorCode = "item_limit_exceeded"
	ErrorTotalSizeExceeded      ErrorCode = "total_size_exceeded"
	ErrorInvalidPreview         ErrorCode = "invalid_preview"
	ErrorInvalidOutput          ErrorCode = "invalid_output"
	ErrorOutputExists           ErrorCode = "output_exists"
	ErrorOutputSymlink          ErrorCode = "output_symlink"
	ErrorWriteFailed            ErrorCode = "write_failed"
)

type Error struct {
	Code      ErrorCode
	Operation string
	Cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Operation == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type Limits struct {
	MaxItems            int
	MaxItemBytes        int64
	MaxTotalBytes       int64
	PerCollectorTimeout time.Duration
	TotalTimeout        time.Duration
}

// Defaults returns an independent copy of the bounded v1 limits.
func Defaults() Limits {
	return Limits{
		MaxItems:            64,
		MaxItemBytes:        1 << 20,
		MaxTotalBytes:       8 << 20,
		PerCollectorTimeout: 3 * time.Second,
		TotalTimeout:        15 * time.Second,
	}
}

type Config struct {
	Limits Limits
}

// CollectedItem is the only collector output accepted by Builder. Text must be valid
// UTF-8 and non-binary. Metadata is the explicit safe alternative for describing binary
// state without embedding raw bytes.
type CollectedItem struct {
	Path     string
	Kind     ItemKind
	Data     []byte
	Metadata map[string]string
}

type Collector interface {
	Name() string
	// Collect must stop when ctx is canceled. Builder invokes collectors synchronously so
	// an uncooperative collector cannot leave a detached timeout goroutine behind.
	Collect(context.Context) ([]CollectedItem, error)
}

type CollectorFunc struct {
	CollectorName string
	CollectFunc   func(context.Context) ([]CollectedItem, error)
}

func (c CollectorFunc) Name() string { return c.CollectorName }

func (c CollectorFunc) Collect(ctx context.Context) ([]CollectedItem, error) {
	if c.CollectFunc == nil {
		return nil, fmt.Errorf("collector function is nil")
	}
	return c.CollectFunc(ctx)
}

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	Format        string            `json:"format"`
	Limits        ManifestLimits    `json:"limits"`
	Collectors    []CollectorResult `json:"collectors"`
	Items         []ItemResult      `json:"items"`
	ContentBytes  int64             `json:"content_bytes"`
	Redactions    int               `json:"redactions"`
}

type ManifestLimits struct {
	MaxItems                  int   `json:"max_items"`
	MaxItemBytes              int64 `json:"max_item_bytes"`
	MaxTotalBytes             int64 `json:"max_total_bytes"`
	PerCollectorTimeoutMillis int64 `json:"per_collector_timeout_millis"`
	TotalTimeoutMillis        int64 `json:"total_timeout_millis"`
}

type CollectorResult struct {
	Name         string     `json:"name"`
	Result       ResultCode `json:"result"`
	ErrorCode    ErrorCode  `json:"error_code,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	ItemCount    int        `json:"item_count"`
}

type ItemResult struct {
	Path       string     `json:"path"`
	Collector  string     `json:"collector"`
	Kind       ItemKind   `json:"kind"`
	Result     ResultCode `json:"result"`
	SizeBytes  int64      `json:"size_bytes"`
	SHA256     string     `json:"sha256"`
	Redactions int        `json:"redactions"`
}

// Preview contains the typed inventory and the exact private bytes that Write will use.
// Bytes returns a copy for local inspection. It performs no filesystem or network work.
type Preview struct {
	Manifest       Manifest
	body           []byte
	digest         string
	manifestDigest string
}

func (p Preview) Bytes() []byte { return append([]byte(nil), p.body...) }

func (p Preview) SizeBytes() int64 { return int64(len(p.body)) }

func (p Preview) SHA256() string { return p.digest }

type WriteResult struct {
	Path      string
	SizeBytes int64
	SHA256    string
	Manifest  Manifest
}

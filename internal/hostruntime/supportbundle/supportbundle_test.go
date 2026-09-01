package supportbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreviewRedactsSecretsFromManifestAndBundle(t *testing.T) {
	t.Parallel()

	secrets := []string{
		"Bearer auth-secret-123",
		"session=very-secret-cookie",
		"json-token-secret",
		"credential-reference-secret",
		"url-user-password",
		"url-user-token",
		"private-key-material",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.abcdefghijklmnopqrstuvwxyz123456",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz123456",
		strings.Join([]string{"xoxb", "1234567890", "abcdefghijklmnop"}, "-"),
		strings.Join([]string{"sk", "live", "abcdefghijklmnopqrstuvwx"}, "_"),
	}
	text := strings.Join([]string{
		"Authorization: " + secrets[0],
		"Cookie: " + secrets[1],
		`{"token":"` + secrets[2] + `","credential_ref":"` + secrets[3] + `","tunnel_id":"tunnel_actionable_123","route_id":"route_actionable_456","correlation_id":"corr_actionable_789"}`,
		"endpoint=https://operator:" + secrets[4] + "@edge.example.test/path",
		"endpoint=https://" + secrets[5] + "@edge.example.test/path",
		"-----BEGIN PRIVATE KEY-----\n" + secrets[6] + "\n-----END PRIVATE KEY-----",
		secrets[7],
		secrets[8],
		secrets[9],
		secrets[10],
		secrets[11],
	}, "\n")

	builder := mustBuilder(t,
		CollectorFunc{CollectorName: "runtime", CollectFunc: func(context.Context) ([]CollectedItem, error) {
			return []CollectedItem{
				{Path: "logs/runtime.log", Kind: ItemKindText, Data: []byte(text)},
				{Path: "state/identity.json", Kind: ItemKindMetadata, Metadata: map[string]string{
					"connector_id":   "connector_actionable_321",
					"credential_ref": "metadata-secret-value",
				}},
			}, nil
		}},
		CollectorFunc{CollectorName: "unavailable", CollectFunc: func(context.Context) ([]CollectedItem, error) {
			return nil, errors.New("/Users/alice/private/customer.log host.customer.example authorization=collector-error-secret")
		}},
	)

	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	manifestBytes, err := json.Marshal(preview.Manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	allBytes := append(preview.Bytes(), manifestBytes...)
	for _, secret := range append(secrets, "metadata-secret-value", "collector-error-secret", "/Users/alice/private/customer.log", "host.customer.example") {
		if bytes.Contains(allBytes, []byte(secret)) {
			t.Fatalf("secret %q present in bundle or manifest", secret)
		}
	}
	for _, actionable := range []string{"tunnel_actionable_123", "route_actionable_456", "corr_actionable_789", "connector_actionable_321"} {
		if !bytes.Contains(allBytes, []byte(actionable)) {
			t.Fatalf("actionable ID %q was not preserved", actionable)
		}
	}
	if preview.Manifest.Redactions < len(secrets) {
		t.Fatalf("redactions = %d, want at least %d", preview.Manifest.Redactions, len(secrets))
	}
	if got := preview.Manifest.Collectors[1]; got.ErrorCode != ErrorCollectorFailed || got.ErrorMessage != "collector failed" {
		t.Fatalf("collector error = %#v", got)
	}

	var document bundleDocument
	if err := json.Unmarshal(preview.Bytes(), &document); err != nil {
		t.Fatalf("Unmarshal bundle: %v", err)
	}
	if document.SchemaVersion != SchemaVersion || document.Manifest.Format != FormatVersion {
		t.Fatalf("unexpected bundle contract: %#v", document)
	}
	if len(document.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(document.Items))
	}
	output := filepath.Join(realTempDir(t), "redacted-support-bundle.json")
	if _, err := builder.Write(t.Context(), preview, output); err != nil {
		t.Fatalf("Write: %v", err)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, secret := range append(secrets, "metadata-secret-value", "collector-error-secret", "/Users/alice/private/customer.log", "host.customer.example") {
		if bytes.Contains(written, []byte(secret)) {
			t.Fatalf("secret %q present in written bundle", secret)
		}
	}
}

func TestPreviewIsDeterministicAndHashesRedactedContent(t *testing.T) {
	t.Parallel()

	collectorA := CollectorFunc{CollectorName: "alpha", CollectFunc: func(context.Context) ([]CollectedItem, error) {
		return []CollectedItem{
			{Path: "system/z.txt", Kind: ItemKindText, Data: []byte("token=secret-value\n")},
			{Path: "health/a.json", Kind: ItemKindMetadata, Metadata: map[string]string{"status": "ready", "tunnel_id": "tunnel_123"}},
		}, nil
	}}
	collectorB := CollectorFunc{CollectorName: "beta", CollectFunc: func(context.Context) ([]CollectedItem, error) {
		return []CollectedItem{{Path: "events/lifecycle.log", Kind: ItemKindText, Data: []byte("attached\n")}}, nil
	}}

	first, err := mustBuilder(t, collectorB, collectorA).Preview(t.Context())
	if err != nil {
		t.Fatalf("first Preview: %v", err)
	}
	second, err := mustBuilder(t, collectorA, collectorB).Preview(t.Context())
	if err != nil {
		t.Fatalf("second Preview: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || first.SHA256() != second.SHA256() {
		t.Fatal("equivalent inputs produced different bundle bytes or hashes")
	}
	want := sha256.Sum256([]byte("token=" + RedactedValue + "\n"))
	for _, item := range first.Manifest.Items {
		if item.Path == "system/z.txt" && item.SHA256 != hex.EncodeToString(want[:]) {
			t.Fatalf("item hash = %s, want %x", item.SHA256, want)
		}
	}
	paths := []string{first.Manifest.Items[0].Path, first.Manifest.Items[1].Path, first.Manifest.Items[2].Path}
	if !sort.StringsAreSorted(paths) {
		t.Fatalf("manifest paths are not sorted: %v", paths)
	}
}

func TestPreviewEnforcesItemCountItemAndTotalBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limits Limits
		items  []CollectedItem
		code   ErrorCode
	}{
		{
			name:   "item count",
			limits: Limits{MaxItems: 1},
			items: []CollectedItem{
				{Path: "logs/a.log", Kind: ItemKindText, Data: []byte("a")},
				{Path: "logs/b.log", Kind: ItemKindText, Data: []byte("b")},
			},
			code: ErrorItemLimitExceeded,
		},
		{
			name:   "item bytes",
			limits: Limits{MaxItemBytes: 3},
			items:  []CollectedItem{{Path: "logs/a.log", Kind: ItemKindText, Data: []byte("four")}},
			code:   ErrorItemTooLarge,
		},
		{
			name:   "encoded total",
			limits: Limits{MaxTotalBytes: 300},
			items:  []CollectedItem{{Path: "logs/a.log", Kind: ItemKindText, Data: []byte("a")}},
			code:   ErrorTotalSizeExceeded,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			builder := mustBuilderConfig(t, Config{Limits: test.limits}, CollectorFunc{
				CollectorName: "bounds",
				CollectFunc:   func(context.Context) ([]CollectedItem, error) { return test.items, nil },
			})
			_, err := builder.Preview(t.Context())
			if errorCode(err) != test.code {
				t.Fatalf("Preview error = %v (%s), want %s", err, errorCode(err), test.code)
			}
		})
	}
}

func TestNewRejectsUnboundedAndDuplicateCollectors(t *testing.T) {
	t.Parallel()

	_, err := New(Config{Limits: Limits{MaxItems: hardMaxItems + 1}})
	if errorCode(err) != ErrorInvalidLimits {
		t.Fatalf("unbounded limits error = %v", err)
	}
	collector := CollectorFunc{CollectorName: "same", CollectFunc: func(context.Context) ([]CollectedItem, error) { return nil, nil }}
	_, err = New(Config{}, collector, collector)
	if errorCode(err) != ErrorDuplicateCollector {
		t.Fatalf("duplicate collector error = %v", err)
	}
	_, err = New(Config{}, CollectorFunc{CollectorName: "../escape", CollectFunc: collector.CollectFunc})
	if errorCode(err) != ErrorInvalidCollector {
		t.Fatalf("invalid collector error = %v", err)
	}
	many := make([]Collector, hardMaxCollectors+1)
	for index := range many {
		many[index] = CollectorFunc{CollectorName: fmt.Sprintf("collector-%d", index), CollectFunc: collector.CollectFunc}
	}
	_, err = New(Config{}, many...)
	if errorCode(err) != ErrorCollectorLimitExceeded {
		t.Fatalf("collector limit error = %v", err)
	}
}

func TestPreviewRejectsUnsafeContentAndPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		item CollectedItem
		code ErrorCode
	}{
		{"traversal", CollectedItem{Path: "logs/../secret", Kind: ItemKindText, Data: []byte("x")}, ErrorInvalidPath},
		{"absolute", CollectedItem{Path: "/logs/a", Kind: ItemKindText, Data: []byte("x")}, ErrorInvalidPath},
		{"backslash", CollectedItem{Path: `logs\a`, Kind: ItemKindText, Data: []byte("x")}, ErrorInvalidPath},
		{"unknown root", CollectedItem{Path: "secrets/a", Kind: ItemKindText, Data: []byte("x")}, ErrorInvalidPath},
		{"invalid utf8", CollectedItem{Path: "logs/a", Kind: ItemKindText, Data: []byte{0xff}}, ErrorInvalidUTF8},
		{"binary nul", CollectedItem{Path: "logs/a", Kind: ItemKindText, Data: []byte{'a', 0, 'b'}}, ErrorBinaryContent},
		{"binary control", CollectedItem{Path: "logs/a", Kind: ItemKindText, Data: []byte{'a', 1, 'b'}}, ErrorBinaryContent},
		{"binary delete", CollectedItem{Path: "logs/a", Kind: ItemKindText, Data: []byte{'a', 0x7f, 'b'}}, ErrorBinaryContent},
		{"metadata with bytes", CollectedItem{Path: "state/a", Kind: ItemKindMetadata, Data: []byte("raw"), Metadata: map[string]string{"kind": "binary"}}, ErrorInvalidMetadata},
		{"invalid metadata value", CollectedItem{Path: "state/a", Kind: ItemKindMetadata, Metadata: map[string]string{"kind": string([]byte{0xff})}}, ErrorInvalidMetadata},
		{"binary metadata value", CollectedItem{Path: "state/a", Kind: ItemKindMetadata, Metadata: map[string]string{"kind": "a\x00b"}}, ErrorInvalidMetadata},
		{"invalid kind", CollectedItem{Path: "logs/a", Kind: ItemKind("binary"), Data: []byte("x")}, ErrorInvalidKind},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			builder := mustBuilder(t, CollectorFunc{CollectorName: "unsafe", CollectFunc: func(context.Context) ([]CollectedItem, error) {
				return []CollectedItem{test.item}, nil
			}})
			_, err := builder.Preview(t.Context())
			if errorCode(err) != test.code {
				t.Fatalf("Preview error = %v (%s), want %s", err, errorCode(err), test.code)
			}
		})
	}
}

func TestPreviewRejectsDuplicateAndHierarchicalPathConflicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		paths []string
		code  ErrorCode
	}{
		{"duplicate", []string{"logs/runtime", "logs/runtime"}, ErrorDuplicatePath},
		{"file then child", []string{"logs/runtime", "logs/runtime/current"}, ErrorPathConflict},
		{"child then file", []string{"logs/runtime/current", "logs/runtime"}, ErrorPathConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			items := make([]CollectedItem, 0, len(test.paths))
			for _, itemPath := range test.paths {
				items = append(items, CollectedItem{Path: itemPath, Kind: ItemKindText, Data: []byte("x")})
			}
			builder := mustBuilder(t, CollectorFunc{CollectorName: "paths", CollectFunc: func(context.Context) ([]CollectedItem, error) { return items, nil }})
			_, err := builder.Preview(t.Context())
			if errorCode(err) != test.code {
				t.Fatalf("Preview error = %v (%s), want %s", err, errorCode(err), test.code)
			}
		})
	}
}

func TestPreviewHonorsCancellationAndDeadlines(t *testing.T) {
	t.Parallel()

	t.Run("caller cancellation", func(t *testing.T) {
		var called atomic.Bool
		builder := mustBuilder(t, CollectorFunc{CollectorName: "never", CollectFunc: func(context.Context) ([]CollectedItem, error) {
			called.Store(true)
			return nil, nil
		}})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := builder.Preview(ctx)
		if errorCode(err) != ErrorCanceled || called.Load() {
			t.Fatalf("Preview error = %v, collector called = %t", err, called.Load())
		}
	})

	t.Run("per collector deadline is typed and partial", func(t *testing.T) {
		builder := mustBuilderConfig(t, Config{Limits: Limits{
			PerCollectorTimeout: 20 * time.Millisecond,
			TotalTimeout:        time.Second,
		}},
			CollectorFunc{CollectorName: "blocked", CollectFunc: func(ctx context.Context) ([]CollectedItem, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}},
			CollectorFunc{CollectorName: "ready", CollectFunc: func(context.Context) ([]CollectedItem, error) {
				return []CollectedItem{{Path: "health/ready.json", Kind: ItemKindMetadata, Metadata: map[string]string{"state": "ready"}}}, nil
			}},
		)
		preview, err := builder.Preview(t.Context())
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if got := preview.Manifest.Collectors[0]; got.ErrorCode != ErrorDeadlineExceeded || got.Result != ResultError {
			t.Fatalf("deadline result = %#v", got)
		}
		if got := preview.Manifest.Collectors[1]; got.Result != ResultOK || got.ItemCount != 1 {
			t.Fatalf("ready result = %#v", got)
		}
	})

	t.Run("total deadline aborts", func(t *testing.T) {
		builder := mustBuilderConfig(t, Config{Limits: Limits{
			PerCollectorTimeout: time.Second,
			TotalTimeout:        20 * time.Millisecond,
		}}, CollectorFunc{CollectorName: "blocked", CollectFunc: func(ctx context.Context) ([]CollectedItem, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}})
		_, err := builder.Preview(t.Context())
		if errorCode(err) != ErrorDeadlineExceeded {
			t.Fatalf("Preview error = %v (%s)", err, errorCode(err))
		}
	})
}

func TestCollectorFailuresAndPanicsAreTypedEntries(t *testing.T) {
	t.Parallel()

	builder := mustBuilder(t,
		CollectorFunc{CollectorName: "failed", CollectFunc: func(context.Context) ([]CollectedItem, error) {
			return nil, errors.New("failed with token=secret-error")
		}},
		CollectorFunc{CollectorName: "panic", CollectFunc: func(context.Context) ([]CollectedItem, error) {
			panic("panic-secret")
		}},
	)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if got := preview.Manifest.Collectors[0]; got.ErrorCode != ErrorCollectorFailed || strings.Contains(got.ErrorMessage, "secret-error") {
		t.Fatalf("failed result = %#v", got)
	}
	if got := preview.Manifest.Collectors[1]; got.ErrorCode != ErrorCollectorPanicked || got.ErrorMessage != "collector panicked" {
		t.Fatalf("panic result = %#v", got)
	}
	if bytes.Contains(preview.Bytes(), []byte("panic-secret")) {
		t.Fatal("panic value leaked into bundle")
	}
}

func TestPreviewDoesNotWriteAndWriteIsAtomicPrivateAndExact(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	output := filepath.Join(directory, "support-bundle.json")
	builder := mustBuilder(t, CollectorFunc{CollectorName: "runtime", CollectFunc: func(context.Context) ([]CollectedItem, error) {
		return []CollectedItem{{Path: "health/runtime.json", Kind: ItemKindMetadata, Metadata: map[string]string{"state": "ready"}}}, nil
	}})
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created output: %v", err)
	}
	result, err := builder.Write(t.Context(), preview, output)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(written, preview.Bytes()) || result.SHA256 != preview.SHA256() || result.SizeBytes != preview.SizeBytes() {
		t.Fatal("written result differs from preview")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorOutputExists {
		t.Fatalf("overwrite error = %v", err)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestValidateOutputPathRejectsUnboundedAndControlCharacters(t *testing.T) {
	t.Parallel()
	directory := realTempDir(t)
	for _, output := range []string{
		filepath.Join(directory, "bundle\nforged.json"),
		filepath.Join(directory, strings.Repeat("a", 4097)),
	} {
		if err := ValidateOutputPath(output); errorCode(err) != ErrorInvalidOutput {
			t.Fatalf("ValidateOutputPath(%q) error = %v", output, err)
		}
	}
}

func TestWriteRejectsSymlinkOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	t.Parallel()

	directory := realTempDir(t)
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	output := filepath.Join(directory, "bundle")
	if err := os.Symlink(target, output); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorOutputSymlink {
		t.Fatalf("Write error = %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", content, err)
	}
}

func TestWriteRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	t.Parallel()

	directory := realTempDir(t)
	realParent := filepath.Join(directory, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	linkedParent := filepath.Join(directory, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	output := filepath.Join(linkedParent, "bundle")
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorInvalidOutput {
		t.Fatalf("Write error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "bundle")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output escaped through parent symlink: %v", err)
	}
}

func TestWriteRejectsSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	t.Parallel()

	directory := realTempDir(t)
	realAncestor := filepath.Join(directory, "real")
	realParent := filepath.Join(realAncestor, "nested", "parent")
	if err := os.MkdirAll(realParent, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	linkedAncestor := filepath.Join(directory, "linked")
	if err := os.Symlink(realAncestor, linkedAncestor); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	output := filepath.Join(linkedAncestor, "nested", "parent", "bundle")
	if err := ValidateOutputPath(output); errorCode(err) != ErrorInvalidOutput {
		t.Fatalf("ValidateOutputPath error = %v", err)
	}
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorInvalidOutput {
		t.Fatalf("Write error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "bundle")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output escaped through ancestor symlink: %v", err)
	}
}

func TestWriteCleansPartialTemporaryFile(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	output := filepath.Join(directory, "support-bundle.json")
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	builder.beforePublish = func(temporary string) error {
		if _, err := os.Stat(temporary); err != nil {
			t.Fatalf("temporary does not exist before publish: %v", err)
		}
		return errors.New("injected publish failure")
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorWriteFailed {
		t.Fatalf("Write error = %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output exists: %v", err)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteNeverReplacesDestinationCreatedImmediatelyBeforePublish(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	output := filepath.Join(directory, "support-bundle.json")
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	builder.beforePublish = func(string) error {
		return os.WriteFile(output, []byte("competing output"), 0o600)
	}
	if _, err := builder.Write(t.Context(), preview, output); errorCode(err) != ErrorOutputExists {
		t.Fatalf("Write error = %v", err)
	}
	content, err := os.ReadFile(output)
	if err != nil || string(content) != "competing output" {
		t.Fatalf("destination was replaced: content=%q error=%v", content, err)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteCancellationImmediatelyBeforePublishLeavesNoOutput(t *testing.T) {
	t.Parallel()

	directory := realTempDir(t)
	output := filepath.Join(directory, "support-bundle.json")
	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	builder.beforePublish = func(string) error {
		cancel()
		return nil
	}
	if _, err := builder.Write(ctx, preview, output); errorCode(err) != ErrorCanceled {
		t.Fatalf("Write error = %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled write published output: %v", err)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteRejectsTamperedPreviewAndCancellation(t *testing.T) {
	t.Parallel()

	builder := mustBuilder(t)
	preview, err := builder.Preview(t.Context())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	tampered := preview
	tampered.body = append([]byte(nil), preview.body...)
	tampered.body[0] ^= 1
	if _, err := builder.Write(t.Context(), tampered, filepath.Join(realTempDir(t), "bundle")); errorCode(err) != ErrorInvalidPreview {
		t.Fatalf("tampered preview error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := builder.Write(ctx, preview, filepath.Join(realTempDir(t), "bundle")); errorCode(err) != ErrorCanceled {
		t.Fatalf("canceled write error = %v", err)
	}
}

func mustBuilder(t *testing.T, collectors ...Collector) *Builder {
	t.Helper()
	return mustBuilderConfig(t, Config{}, collectors...)
}

func realTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return directory
}

func mustBuilderConfig(t *testing.T, config Config, collectors ...Collector) *Builder {
	t.Helper()
	builder, err := New(config, collectors...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return builder
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".paperboat-support-bundle-") {
			t.Fatalf("partial temporary file remains: %s", entry.Name())
		}
	}
}

func ExampleBuilder() {
	builder, _ := New(Config{}, CollectorFunc{
		CollectorName: "health",
		CollectFunc: func(context.Context) ([]CollectedItem, error) {
			return []CollectedItem{{
				Path:     "health/summary.json",
				Kind:     ItemKindMetadata,
				Metadata: map[string]string{"state": "ready"},
			}}, nil
		},
	})
	preview, _ := builder.Preview(context.Background())
	fmt.Println(preview.Manifest.SchemaVersion)
	// Output: paperboat.support_bundle.v1
}

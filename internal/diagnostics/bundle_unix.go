//go:build darwin || linux

package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	BundleSchemaV1     = "paperboat.diagnostic-bundle/v1"
	MaximumBundleBytes = 25 << 20
	maximumEventExport = 20 << 20
	maximumStatusBytes = 1 << 20
)

type BundleConfig struct {
	Directory string
	OwnerUID  int
	Recorder  *Recorder
	Status    json.RawMessage
	Clock     func() time.Time
}

type Bundle struct {
	Schema      string    `json:"schema"`
	Correlation string    `json:"correlation"`
	CreatedAt   time.Time `json:"created_at"`
	Path        string    `json:"path"`
	Bytes       int64     `json:"bytes"`
	Categories  []string  `json:"categories"`
}

func (b Bundle) Validate() error {
	if b.Schema != BundleSchemaV1 || len(b.Correlation) != 35 || b.Correlation[:3] != "pb-" || !safeHex(b.Correlation[3:]) || b.CreatedAt.IsZero() || b.CreatedAt.Location() != time.UTC || !filepath.IsAbs(b.Path) || filepath.Clean(b.Path) != b.Path || b.Bytes <= 0 || b.Bytes > MaximumBundleBytes || len(b.Categories) != 4 {
		return ErrInvalid
	}
	want := []string{"manifest", "recent_events", "redacted_events", "status"}
	for index := range want {
		if b.Categories[index] != want[index] {
			return ErrInvalid
		}
	}
	return nil
}

type bundleManifest struct {
	Schema         string    `json:"schema"`
	Correlation    string    `json:"correlation"`
	CreatedAt      time.Time `json:"created_at"`
	Categories     []string  `json:"categories"`
	DroppedRecords uint64    `json:"dropped_records"`
	DroppedBytes   uint64    `json:"dropped_bytes"`
}

func CreateBundle(ctx context.Context, config BundleConfig) (Bundle, error) {
	if ctx == nil || config.Recorder == nil || !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory || config.OwnerUID < 0 || len(config.Status) == 0 || len(config.Status) > maximumStatusBytes || !json.Valid(config.Status) {
		return Bundle{}, ErrInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if err := ensureDiagnosticDirectory(config.Directory, config.OwnerUID); err != nil {
		return Bundle{}, err
	}
	correlation, err := newCorrelation()
	if err != nil {
		return Bundle{}, err
	}
	createdAt := config.Clock().UTC()
	if err := config.Recorder.Flush(ctx); err != nil {
		return Bundle{}, err
	}
	events, err := config.Recorder.ReadDiskTail(ctx, maximumEventExport)
	if err != nil {
		return Bundle{}, err
	}
	recent, err := marshalEvents(config.Recorder.Recent())
	if err != nil {
		return Bundle{}, err
	}
	categories := []string{"manifest", "recent_events", "redacted_events", "status"}
	stats := config.Recorder.Stats()
	manifest, err := json.Marshal(bundleManifest{Schema: BundleSchemaV1, Correlation: correlation, CreatedAt: createdAt, Categories: categories, DroppedRecords: stats.DroppedRecords, DroppedBytes: stats.DroppedBytes})
	if err != nil {
		return Bundle{}, err
	}
	temporary, err := os.OpenFile(filepath.Join(config.Directory, ".bugreport-"+correlation+".tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Bundle{}, err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	archive := zip.NewWriter(temporary)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", append(manifest, '\n')}, {"recent-events.ndjson", recent}, {"events.ndjson", events}, {"status.json", append(bytes.TrimSpace(config.Status), '\n')}} {
		writer, createErr := archive.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Deflate})
		if createErr != nil {
			return Bundle{}, createErr
		}
		if _, writeErr := writer.Write(entry.data); writeErr != nil {
			return Bundle{}, writeErr
		}
	}
	if err := archive.Close(); err != nil {
		return Bundle{}, err
	}
	if err := temporary.Sync(); err != nil {
		return Bundle{}, err
	}
	if err := temporary.Close(); err != nil {
		return Bundle{}, err
	}
	info, err := os.Stat(temporaryPath)
	if err != nil || !validDiagnosticFile(info, config.OwnerUID) || info.Size() <= 0 || info.Size() > MaximumBundleBytes {
		return Bundle{}, errors.Join(ErrInvalid, err)
	}
	finalPath := filepath.Join(config.Directory, "bugreport-"+correlation+".zip")
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, ErrInvalid
	}
	//paperboat:allow-source-policy atomic-replacement owner=diagnostics reason=verified-bundle-publication
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return Bundle{}, err
	}
	if err := syncDirectory(config.Directory); err != nil {
		_ = removeDiagnosticFile(finalPath, config.OwnerUID)
		return Bundle{}, err
	}
	keep = true
	return Bundle{Schema: BundleSchemaV1, Correlation: correlation, CreatedAt: createdAt, Path: finalPath, Bytes: info.Size(), Categories: categories}, nil
}

func safeHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func marshalEvents(events []Event) ([]byte, error) {
	var result bytes.Buffer
	for _, event := range events {
		if event.Validate() != nil {
			return nil, ErrInvalid
		}
		encoded, err := json.Marshal(event)
		if err != nil || result.Len()+len(encoded)+1 > MaximumRecordBytes*MemoryCapacity {
			return nil, ErrInvalid
		}
		result.Write(encoded)
		result.WriteByte('\n')
	}
	return result.Bytes(), nil
}

func newCorrelation() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate bugreport correlation: %w", err)
	}
	return "pb-" + hex.EncodeToString(value[:]), nil
}

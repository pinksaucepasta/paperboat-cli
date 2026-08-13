//go:build darwin || linux

package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	MaximumRecordBytes   = 64 << 10
	DefaultMaximumBytes  = 50 << 20
	DefaultRetention     = 7 * 24 * time.Hour
	defaultSegmentBytes  = 1 << 20
	defaultQueueCapacity = 256
)

type DiskConfig struct {
	Directory     string
	OwnerUID      int
	MaximumBytes  int64
	Retention     time.Duration
	SegmentBytes  int64
	QueueCapacity int
	Clock         func() time.Time
}

type DiskStats struct {
	DroppedRecords uint64
	DroppedBytes   uint64
	PersistedBytes uint64
}

type diskRecord struct {
	encoded []byte
	barrier chan struct{}
}

type DiskRing struct {
	config DiskConfig
	queue  chan diskRecord
	done   chan struct{}

	mu     sync.Mutex
	closed bool
	err    error

	droppedRecords atomic.Uint64
	droppedBytes   atomic.Uint64
	persistedBytes atomic.Uint64
}

func NewDiskRing(config DiskConfig) (*DiskRing, error) {
	if !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory || config.OwnerUID < 0 {
		return nil, ErrInvalid
	}
	if config.MaximumBytes == 0 {
		config.MaximumBytes = DefaultMaximumBytes
	}
	if config.Retention == 0 {
		config.Retention = DefaultRetention
	}
	if config.SegmentBytes == 0 {
		config.SegmentBytes = defaultSegmentBytes
	}
	if config.QueueCapacity == 0 {
		config.QueueCapacity = defaultQueueCapacity
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaximumBytes < MaximumRecordBytes || config.MaximumBytes > DefaultMaximumBytes || config.Retention <= 0 || config.Retention > DefaultRetention || config.SegmentBytes < MaximumRecordBytes || config.SegmentBytes > config.MaximumBytes || config.QueueCapacity < 1 || config.QueueCapacity > 4096 {
		return nil, ErrInvalid
	}
	if err := ensureDiagnosticDirectory(config.Directory, config.OwnerUID); err != nil {
		return nil, err
	}
	ring := &DiskRing{config: config, queue: make(chan diskRecord, config.QueueCapacity), done: make(chan struct{})}
	if err := ring.recover(); err != nil {
		return nil, err
	}
	go ring.run()
	return ring, nil
}

func (r *DiskRing) Record(event Event) error {
	if r == nil || event.Validate() != nil {
		return ErrInvalid
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded)+1 > MaximumRecordBytes {
		return ErrInvalid
	}
	encoded = append(encoded, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	select {
	case r.queue <- diskRecord{encoded: encoded}:
		return nil
	default:
		r.droppedRecords.Add(1)
		r.droppedBytes.Add(uint64(len(encoded)))
		return nil
	}
}

func (r *DiskRing) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.mu.Unlock()
	<-r.done
	r.mu.Lock()
	err := r.err
	r.mu.Unlock()
	return err
}

func (r *DiskRing) Flush(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalid
	}
	barrier := make(chan struct{})
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return os.ErrClosed
	}
	select {
	case r.queue <- diskRecord{barrier: barrier}:
		r.mu.Unlock()
	case <-ctx.Done():
		r.mu.Unlock()
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *DiskRing) Stats() DiskStats {
	if r == nil {
		return DiskStats{}
	}
	return DiskStats{DroppedRecords: r.droppedRecords.Load(), DroppedBytes: r.droppedBytes.Load(), PersistedBytes: r.persistedBytes.Load()}
}

func (r *DiskRing) run() {
	defer close(r.done)
	for record := range r.queue {
		if record.barrier != nil {
			close(record.barrier)
			continue
		}
		if err := r.persist(record.encoded); err != nil {
			r.mu.Lock()
			r.err = errors.Join(r.err, err)
			r.mu.Unlock()
			r.droppedRecords.Add(1)
			r.droppedBytes.Add(uint64(len(record.encoded)))
		}
	}
}

func (r *DiskRing) persist(encoded []byte) error {
	segments, total, err := r.segments()
	if err != nil {
		return err
	}
	for total+int64(len(encoded)) > r.config.MaximumBytes && len(segments) > 0 {
		if err := removeDiagnosticFile(segments[0].path, r.config.OwnerUID); err != nil {
			return err
		}
		total -= segments[0].size
		segments = segments[1:]
	}
	if int64(len(encoded)) > r.config.MaximumBytes-total {
		return errors.New("diagnostic ring capacity exhausted")
	}
	path := ""
	if len(segments) > 0 && segments[len(segments)-1].size+int64(len(encoded)) <= r.config.SegmentBytes {
		path = segments[len(segments)-1].path
	}
	if path == "" {
		path, err = r.createSegment()
		if err != nil {
			return err
		}
	}
	file, err := openDiagnosticAppend(path, r.config.OwnerUID)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr)
	}
	r.persistedBytes.Add(uint64(len(encoded)))
	return nil
}

type segmentInfo struct {
	path    string
	size    int64
	modTime time.Time
}

func (r *DiskRing) segments() ([]segmentInfo, int64, error) {
	entries, err := os.ReadDir(r.config.Directory)
	if err != nil {
		return nil, 0, err
	}
	result := make([]segmentInfo, 0, len(entries))
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "events-") || filepath.Ext(entry.Name()) != ".ndjson" {
			continue
		}
		path := filepath.Join(r.config.Directory, entry.Name())
		info, err := verifiedDiagnosticFile(path, r.config.OwnerUID)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, segmentInfo{path: path, size: info.Size(), modTime: info.ModTime()})
		total += info.Size()
	}
	sort.Slice(result, func(i, j int) bool { return result[i].path < result[j].path })
	return result, total, nil
}

func (r *DiskRing) createSegment() (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name := fmt.Sprintf("events-%020d-%02d.ndjson", r.config.Clock().UTC().UnixNano(), attempt)
		path := filepath.Join(r.config.Directory, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
		return path, syncDirectory(r.config.Directory)
	}
	return "", errors.New("diagnostic segment name exhausted")
}

func (r *DiskRing) recover() error {
	segments, total, err := r.segments()
	if err != nil {
		return err
	}
	cutoff := r.config.Clock().UTC().Add(-r.config.Retention)
	for _, segment := range segments {
		if segment.modTime.Before(cutoff) {
			if err := removeDiagnosticFile(segment.path, r.config.OwnerUID); err != nil {
				return err
			}
			total -= segment.size
			continue
		}
		if err := recoverSegment(segment.path, r.config.OwnerUID); err != nil {
			return err
		}
	}
	segments, total, err = r.segments()
	if err != nil {
		return err
	}
	for total > r.config.MaximumBytes && len(segments) > 0 {
		if err := removeDiagnosticFile(segments[0].path, r.config.OwnerUID); err != nil {
			return err
		}
		total -= segments[0].size
		segments = segments[1:]
	}
	return nil
}

func (r *DiskRing) ReadAll(ctx context.Context, maximum int64) ([]byte, error) {
	if r == nil || ctx == nil || maximum <= 0 || maximum > r.config.MaximumBytes {
		return nil, ErrInvalid
	}
	segments, _, err := r.segments()
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	for _, segment := range segments {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if int64(output.Len())+segment.size > maximum {
			return nil, errors.New("diagnostic export exceeds limit")
		}
		file, err := openDiagnosticRead(segment.path, r.config.OwnerUID)
		if err != nil {
			return nil, err
		}
		_, copyErr := io.CopyN(&output, file, segment.size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return nil, errors.Join(copyErr, closeErr)
		}
	}
	return output.Bytes(), nil
}

func (r *DiskRing) ReadTail(ctx context.Context, maximum int64) ([]byte, error) {
	if r == nil || ctx == nil || maximum <= 0 || maximum > r.config.MaximumBytes {
		return nil, ErrInvalid
	}
	segments, _, err := r.segments()
	if err != nil {
		return nil, err
	}
	start := len(segments)
	var selected int64
	for start > 0 && selected+segments[start-1].size <= maximum {
		start--
		selected += segments[start].size
	}
	var output bytes.Buffer
	for _, segment := range segments[start:] {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		file, err := openDiagnosticRead(segment.path, r.config.OwnerUID)
		if err != nil {
			return nil, err
		}
		_, copyErr := io.CopyN(&output, file, segment.size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return nil, errors.Join(copyErr, closeErr)
		}
	}
	return output.Bytes(), nil
}

func recoverSegment(path string, ownerUID int) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !validDiagnosticFile(info, ownerUID) {
		_ = file.Close()
		return ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, info.Size()+1))
	if err != nil || int64(len(data)) != info.Size() {
		_ = file.Close()
		return errors.Join(ErrInvalid, err)
	}
	validOffset := 0
	for validOffset < len(data) {
		relativeEnd := bytes.IndexByte(data[validOffset:], '\n')
		if relativeEnd < 0 || relativeEnd+1 > MaximumRecordBytes {
			break
		}
		end := validOffset + relativeEnd
		var event Event
		if json.Unmarshal(data[validOffset:end], &event) != nil || event.Validate() != nil {
			break
		}
		validOffset = end + 1
	}
	if int64(validOffset) != info.Size() {
		if err := file.Truncate(int64(validOffset)); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
	}
	return file.Close()
}

func ensureDiagnosticDirectory(path string, ownerUID int) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || fileUID(info) != ownerUID {
		return ErrInvalid
	}
	return nil
}

func verifiedDiagnosticFile(path string, ownerUID int) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !validDiagnosticFile(info, ownerUID) {
		return nil, ErrInvalid
	}
	return info, nil
}

func validDiagnosticFile(info os.FileInfo, ownerUID int) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && fileUID(info) == ownerUID
}

func openDiagnosticAppend(path string, ownerUID int) (*os.File, error) {
	before, err := verifiedDiagnosticFile(path, ownerUID)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !validDiagnosticFile(info, ownerUID) || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func openDiagnosticRead(path string, ownerUID int) (*os.File, error) {
	before, err := verifiedDiagnosticFile(path, ownerUID)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !validDiagnosticFile(info, ownerUID) || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

func removeDiagnosticFile(path string, ownerUID int) error {
	if _, err := verifiedDiagnosticFile(path, ownerUID); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func fileUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

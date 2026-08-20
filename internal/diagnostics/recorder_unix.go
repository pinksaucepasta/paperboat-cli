package diagnostics

import (
	"context"
	"errors"
	"time"
)

type Recorder struct {
	memory *MemoryRing
	disk   *DiskRing
	clock  func() time.Time
}

func NewRecorder(config DiskConfig) (*Recorder, error) {
	disk, err := NewDiskRing(config)
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Recorder{memory: &MemoryRing{}, disk: disk, clock: clock}, nil
}

func (r *Recorder) Record(category, code, severity string, fields map[string]string) error {
	if r == nil || r.memory == nil || r.disk == nil || r.clock == nil {
		return ErrInvalid
	}
	event, err := NewEvent(r.clock().UTC(), category, code, severity, fields)
	if err != nil {
		return err
	}
	return errors.Join(r.memory.Record(event), r.disk.Record(event))
}

func (r *Recorder) Recent() []Event {
	if r == nil || r.memory == nil {
		return nil
	}
	return r.memory.Snapshot()
}

func (r *Recorder) ReadDisk(ctx context.Context, maximum int64) ([]byte, error) {
	if r == nil || r.disk == nil {
		return nil, ErrInvalid
	}
	return r.disk.ReadAll(ctx, maximum)
}

func (r *Recorder) ReadDiskTail(ctx context.Context, maximum int64) ([]byte, error) {
	if r == nil || r.disk == nil {
		return nil, ErrInvalid
	}
	return r.disk.ReadTail(ctx, maximum)
}

func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil || r.disk == nil {
		return ErrInvalid
	}
	return r.disk.Flush(ctx)
}

func (r *Recorder) Stats() DiskStats {
	if r == nil || r.disk == nil {
		return DiskStats{}
	}
	return r.disk.Stats()
}

func (r *Recorder) Close() error {
	if r == nil || r.disk == nil {
		return nil
	}
	return r.disk.Close()
}

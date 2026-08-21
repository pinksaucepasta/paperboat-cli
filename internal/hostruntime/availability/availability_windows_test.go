package availability

import (
	"context"
	"testing"
	"time"
)

type windowsImmediateAvailabilityResolver struct{}

func (windowsImmediateAvailabilityResolver) Resolve(context.Context) (Resolution, error) {
	return Resolution{Schema: PolicySchemaV1, UserMachineID: "um_windows", Mode: "keep_awake", Version: 7}, nil
}

type windowsImmediateAvailabilityHost struct{}

func (windowsImmediateAvailabilityHost) Apply(_ context.Context, policy Resolution) (Observation, error) {
	return Observation{
		Schema:             PolicySchemaV1,
		Mode:               policy.Mode,
		Version:            policy.Version,
		Status:             "applied",
		ObservedAt:         time.Now().UTC(),
		HostServiceVersion: "test",
		HostServiceScope:   "system",
		UpdateHealth:       "healthy",
	}, nil
}

func TestWindowsServicePublishesInitialObservationBeforeStartReturns(t *testing.T) {
	service, err := NewService(windowsImmediateAvailabilityResolver{}, windowsImmediateAvailabilityHost{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	observation := service.Observation()
	if observation == nil || observation.Mode != "keep_awake" || observation.Version != 7 || observation.Status != "applied" {
		t.Fatalf("initial Windows availability observation=%+v", observation)
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := service.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
}

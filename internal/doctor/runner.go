package doctor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Probe struct {
	Code string
	Run  func(context.Context) Check
}

type Config struct {
	Timeout      time.Duration
	ProbeTimeout time.Duration
	Clock        func() time.Time
	Correlation  func() (string, error)
}

func Run(ctx context.Context, config Config, machine *Machine, probes []Probe) (Report, error) {
	if ctx == nil || config.Timeout <= 0 || config.Timeout > time.Minute || config.ProbeTimeout <= 0 || config.ProbeTimeout > config.Timeout || config.Clock == nil || config.Correlation == nil || len(probes) == 0 || len(probes) > 64 {
		return Report{}, errors.New("invalid doctor runner configuration")
	}
	correlationID, err := config.Correlation()
	if err != nil || !safeIdentifier.MatchString(correlationID) {
		return Report{}, errors.New("create doctor correlation")
	}
	runCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	checks := make([]Check, len(probes))
	var wait sync.WaitGroup
	for index, probe := range probes {
		if !safeIdentifier.MatchString(probe.Code) || probe.Run == nil {
			return Report{}, errors.New("invalid doctor probe")
		}
		wait.Add(1)
		go func(index int, probe Probe) {
			defer wait.Done()
			probeCtx, probeCancel := context.WithTimeout(runCtx, config.ProbeTimeout)
			defer probeCancel()
			check := probe.Run(probeCtx)
			if probeCtx.Err() != nil {
				check = Check{Category: "diagnostics", Code: probe.Code, Status: StatusUnavailable, Summary: "The check did not complete within its deadline."}
			}
			if check.Code == "" {
				check.Code = probe.Code
			}
			if check.Code != probe.Code {
				check = Check{Category: "diagnostics", Code: probe.Code, Status: StatusFail, Summary: "The check returned an invalid result.", Recovery: "Update Paperboat and run pb doctor again."}
			}
			checks[index] = check
		}(index, probe)
	}
	wait.Wait()
	checks, err = normalize(checks)
	if err != nil {
		return Report{}, fmt.Errorf("validate doctor results: %w", err)
	}
	report := Report{Schema: SchemaV1, CorrelationID: correlationID, CheckedAt: config.Clock().UTC(), Overall: overall(checks), Machine: machine, Checks: checks}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

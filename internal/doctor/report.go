package doctor

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaV1 = "paperboat.doctor/v1"

const (
	StatusPass        = "pass"
	StatusWarning     = "warning"
	StatusFail        = "fail"
	StatusUnavailable = "unavailable"
)

var safeIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)

type Check struct {
	Category     string  `json:"category"`
	Code         string  `json:"code"`
	Status       string  `json:"status"`
	Summary      string  `json:"summary"`
	Recovery     string  `json:"recovery,omitempty"`
	SelectedPath string  `json:"selected_path,omitempty"`
	RelayRegion  string  `json:"relay_region,omitempty"`
	RTTMS        float64 `json:"rtt_ms,omitempty"`
	PTOs         uint32  `json:"ptos,omitempty"`
	Fallback     string  `json:"fallback,omitempty"`
}

type Machine struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
}

type Report struct {
	Schema        string    `json:"schema"`
	CorrelationID string    `json:"correlation_id"`
	CheckedAt     time.Time `json:"checked_at"`
	Overall       string    `json:"overall"`
	Machine       *Machine  `json:"machine,omitempty"`
	Checks        []Check   `json:"checks"`
}

func (r Report) Validate() error {
	if r.Schema != SchemaV1 || !safeIdentifier.MatchString(r.CorrelationID) || r.CheckedAt.IsZero() || !oneOf(r.Overall, "healthy", "degraded", "unhealthy") || len(r.Checks) == 0 || len(r.Checks) > 64 {
		return errors.New("invalid doctor report")
	}
	if r.Machine != nil && (!safeIdentifier.MatchString(r.Machine.ID) || !safeText(r.Machine.Alias, 256)) {
		return errors.New("invalid doctor machine")
	}
	previous := ""
	seen := make(map[string]bool, len(r.Checks))
	for _, check := range r.Checks {
		if err := check.Validate(); err != nil || seen[check.Code] || previous > check.Code {
			return errors.New("invalid doctor checks")
		}
		seen[check.Code] = true
		previous = check.Code
	}
	if r.Overall != overall(r.Checks) {
		return errors.New("invalid doctor overall state")
	}
	return nil
}

func (c Check) Validate() error {
	if !safeIdentifier.MatchString(c.Category) || !safeIdentifier.MatchString(c.Code) || !oneOf(c.Status, StatusPass, StatusWarning, StatusFail, StatusUnavailable) || !safeText(c.Summary, 512) || c.Recovery != "" && !safeText(c.Recovery, 512) {
		return errors.New("invalid doctor check")
	}
	if (c.Status == StatusFail || c.Status == StatusWarning) && c.Recovery == "" {
		return errors.New("doctor warning or failure requires recovery")
	}
	hasTransport := c.SelectedPath != "" || c.RelayRegion != "" || c.RTTMS != 0 || c.PTOs != 0 || c.Fallback != ""
	if hasTransport && (c.Code != "peer_reachability" || !oneOf(c.SelectedPath, "direct", "relay", "wss") || c.RTTMS <= 0 || c.RTTMS > 60_000 || c.PTOs > 1_000 || !oneOf(c.Fallback, "none", "direct_not_selected", "quic_not_selected") || c.SelectedPath == "direct" && (c.RelayRegion != "" || c.Fallback != "none") || c.SelectedPath != "direct" && !safeIdentifier.MatchString(c.RelayRegion)) {
		return errors.New("invalid doctor transport evidence")
	}
	return nil
}

func normalize(checks []Check) ([]Check, error) {
	result := append([]Check(nil), checks...)
	sort.Slice(result, func(i, j int) bool { return result[i].Code < result[j].Code })
	for index := range result {
		if err := result[index].Validate(); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1].Code == result[index].Code {
			return nil, errors.New("duplicate doctor check")
		}
	}
	return result, nil
}

func overall(checks []Check) string {
	state := "healthy"
	for _, check := range checks {
		if check.Status == StatusFail {
			return "unhealthy"
		}
		if check.Status == StatusWarning || check.Status == StatusUnavailable {
			state = "degraded"
		}
	}
	return state
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func safeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

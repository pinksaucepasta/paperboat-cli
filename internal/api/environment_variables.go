package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvironmentVariableScope is the scope owned by an environment-variable
// collection. The global scope applies to every connected host; the machine
// scope applies only to the selected enrolled machine.
type EnvironmentVariableScope string

const (
	EnvironmentVariableScopeGlobal  EnvironmentVariableScope = "global"
	EnvironmentVariableScopeMachine EnvironmentVariableScope = "machine"

	// These limits are part of the runtime injection contract. Keeping the
	// client-side check here avoids sending a value that the host could never
	// apply, while the server remains authoritative.
	MaximumEnvironmentVariableNameBytes  = 128
	MaximumEnvironmentVariableValueBytes = 32_767
	MaximumEnvironmentVariables          = 128
)

// EnvironmentVariable is redacted metadata. Values are intentionally absent
// from this type so API callers cannot accidentally print or persist them.
type EnvironmentVariable struct {
	Scope      EnvironmentVariableScope `json:"scope"`
	MachineID  string                   `json:"machine_id,omitempty"`
	Name       string                   `json:"name"`
	Configured bool                     `json:"configured"`
	Version    int64                    `json:"version"`
	UpdatedAt  time.Time                `json:"updated_at"`
	// ETag is response metadata and is never serialized into JSON output.
	ETag string `json:"-"`
}

// EnvironmentVariableCollection is the server-authoritative metadata for one
// scope. It never contains environment values.
type EnvironmentVariableCollection struct {
	Scope                 EnvironmentVariableScope `json:"scope"`
	MachineID             string                   `json:"machine_id,omitempty"`
	ScopeState            string                   `json:"scope_state,omitempty"`
	KeyState              string                   `json:"key_state"`
	Version               int64                    `json:"version"`
	KeyEpoch              int64                    `json:"key_epoch,omitempty"`
	ManifestID            string                   `json:"manifest_id,omitempty"`
	Variables             []EnvironmentVariable    `json:"variables"`
	Status                string                   `json:"status,omitempty"`
	AppliedGlobalVersion  *int64                   `json:"applied_global_version,omitempty"`
	AppliedMachineVersion *int64                   `json:"applied_machine_version,omitempty"`
	AppliedState          string                   `json:"applied_state,omitempty"`
	ErrorCode             string                   `json:"error_code,omitempty"`
	ObservedAt            *time.Time               `json:"observed_at,omitempty"`

	// ETag is the strong scope version used for manifest mutation If-Match.
	ETag string `json:"-"`
}

// ListEnvironmentVariables returns redacted metadata for the global scope
// when machineID is empty, or for one enrolled machine otherwise.
func (c *Client) ListEnvironmentVariables(ctx context.Context, machineID string) (EnvironmentVariableCollection, error) {
	machineID = strings.TrimSpace(machineID)
	path := "/v1/environment-variables"
	if machineID != "" {
		path = "/v1/machines/" + url.PathEscape(machineID) + "/environment-variables"
	}

	var out EnvironmentVariableCollection
	var headers http.Header
	err := c.doRequestMeta(ctx, http.MethodGet, path, nil, &out, environmentNoStoreRequestHeaders(nil), true, &headers)
	if err != nil {
		return EnvironmentVariableCollection{}, err
	}
	if err := validateEnvironmentNoStore(headers); err != nil {
		return EnvironmentVariableCollection{}, err
	}
	out.ETag = strings.TrimSpace(headers.Get("ETag"))
	if err := validateEnvironmentVariableCollection(out, machineID); err != nil {
		return EnvironmentVariableCollection{}, err
	}
	if out.ETag == "" {
		return EnvironmentVariableCollection{}, errors.New("paperboat-server returned no environment-variable ETag")
	}
	if err := validateEnvironmentVariableETagForVersion(out.ETag, machineID, out.Version); err != nil {
		return EnvironmentVariableCollection{}, err
	}
	if out.Variables == nil {
		out.Variables = []EnvironmentVariable{}
	}
	for index := range out.Variables {
		out.Variables[index].ETag = out.ETag
	}
	return out, nil
}

func validateEnvironmentVariableName(name string) error {
	if name == "" || len(name) > MaximumEnvironmentVariableNameBytes || !environmentVariableNamePattern.MatchString(name) {
		return errors.New("environment variable name must be 1-128 ASCII letters, numbers, or underscores and start with a letter or underscore")
	}
	upperName := strings.ToUpper(name)
	if strings.HasPrefix(upperName, "PAPERBOAT_") || strings.HasPrefix(upperName, "LD_") || strings.HasPrefix(upperName, "DYLD_") || upperName == "NODE_OPTIONS" || upperName == "PYTHONPATH" || upperName == "PYTHONHOME" || upperName == "GOTRACEBACK" {
		return errors.New("environment variable name is reserved")
	}
	return nil
}

func validateEnvironmentVariableMetadata(value EnvironmentVariable, machineID, requestedName string, expectedVersion int64) error {
	if err := validateEnvironmentVariableName(value.Name); err != nil || !strings.EqualFold(value.Name, requestedName) {
		return errors.New("paperboat-server returned invalid environment-variable metadata")
	}
	if value.Scope != expectedEnvironmentVariableScope(machineID) || machineID != "" && value.MachineID != machineID || machineID == "" && value.MachineID != "" || value.Version < 1 || value.Version != expectedVersion || !value.Configured || value.UpdatedAt.IsZero() {
		return errors.New("paperboat-server returned invalid environment-variable metadata")
	}
	return nil
}

func validateEnvironmentVariableCollection(value EnvironmentVariableCollection, machineID string) error {
	if value.Scope != expectedEnvironmentVariableScope(machineID) || machineID != "" && value.MachineID != machineID || machineID == "" && value.MachineID != "" || value.Version < 0 || len(value.Variables) > MaximumEnvironmentVariables {
		return errors.New("paperboat-server returned invalid environment-variable collection")
	}
	switch value.KeyState {
	case "key_authorization_required":
		if value.Version != 0 || value.ScopeState != "" || value.KeyEpoch != 0 || value.ManifestID != "" || len(value.Variables) != 0 {
			return errors.New("paperboat-server returned invalid uninitialized environment-variable scope")
		}
	case "ready", "rotation_required":
		if value.Version < 1 || value.KeyEpoch < 1 || !environmentVariableDocumentIDPattern.MatchString(value.ManifestID) || value.ScopeState != "active" && value.ScopeState != "retired" || machineID == "" && value.ScopeState != "active" {
			return errors.New("paperboat-server returned invalid encrypted environment-variable scope metadata")
		}
	default:
		return errors.New("paperboat-server returned invalid environment-variable key state")
	}
	if machineID == "" {
		if value.Status != "" || value.AppliedGlobalVersion != nil || value.AppliedMachineVersion != nil || value.AppliedState != "" || value.ErrorCode != "" || value.ObservedAt != nil {
			return errors.New("paperboat-server returned machine status for the global environment-variable scope")
		}
	} else if err := validateEnvironmentVariableObservation(value); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(value.Variables))
	for index := range value.Variables {
		item := value.Variables[index]
		if err := validateEnvironmentVariableName(item.Name); err != nil || item.Scope != value.Scope || item.MachineID != value.MachineID || item.Version != value.Version || !item.Configured || item.UpdatedAt.IsZero() {
			return errors.New("paperboat-server returned invalid environment-variable metadata")
		}
		key := strings.ToUpper(item.Name)
		if _, ok := seen[key]; ok {
			return errors.New("paperboat-server returned duplicate environment-variable metadata")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateEnvironmentVariableObservation(value EnvironmentVariableCollection) error {
	switch value.Status {
	case "pending", "applied", "failed", "offline":
	default:
		return errors.New("paperboat-server returned invalid environment-variable status")
	}
	for _, version := range []*int64{value.AppliedGlobalVersion, value.AppliedMachineVersion} {
		if version != nil && *version < 0 {
			return errors.New("paperboat-server returned invalid environment-variable applied version")
		}
	}
	if value.AppliedState != "" && value.AppliedState != "pending" && value.AppliedState != "applied" && value.AppliedState != "failed" {
		return errors.New("paperboat-server returned invalid environment-variable applied state")
	}
	if value.ErrorCode != "" {
		if len(value.ErrorCode) > 64 || !environmentVariableErrorCodePattern.MatchString(value.ErrorCode) {
			return errors.New("paperboat-server returned invalid environment-variable error code")
		}
	}
	if value.ObservedAt != nil && value.ObservedAt.IsZero() {
		return errors.New("paperboat-server returned invalid environment-variable observation time")
	}
	return nil
}

func expectedEnvironmentVariableScope(machineID string) EnvironmentVariableScope {
	if machineID == "" {
		return EnvironmentVariableScopeGlobal
	}
	return EnvironmentVariableScopeMachine
}

func validateEnvironmentVariableETagForVersion(etag, machineID string, version int64) error {
	if version < 0 {
		return errors.New("environment-variable version is invalid")
	}
	if err := validateEnvironmentVariableETagForTarget(etag, machineID); err != nil {
		return err
	}
	if want := environmentVariableETag(machineID, version); etag != want {
		return errors.New("environment-variable ETag does not match scope version")
	}
	return nil
}

func validateEnvironmentVariableETagForTarget(etag, machineID string) error {
	_, err := parseEnvironmentVariableETag(etag, machineID)
	return err
}

func parseEnvironmentVariableETag(etag, machineID string) (int64, error) {
	if etag == "" || len(etag) > 256 || strings.ContainsAny(etag, "\r\n") {
		return 0, errors.New("environment-variable ETag is required")
	}
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		return 0, errors.New("environment-variable ETag must be strong")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(etag, `"`), `"`)
	prefix := "environment-global-"
	if machineID != "" {
		prefix = "environment-machine-" + machineID + "-"
	}
	if !strings.HasPrefix(body, prefix) {
		return 0, errors.New("environment-variable ETag does not match scope")
	}
	versionText := strings.TrimPrefix(body, prefix)
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 0 || strconv.FormatInt(version, 10) != versionText {
		return 0, errors.New("environment-variable ETag has an invalid version")
	}
	return version, nil
}

func environmentVariableETag(machineID string, version int64) string {
	if machineID == "" {
		return fmt.Sprintf(`"environment-global-%d"`, version)
	}
	return fmt.Sprintf(`"environment-machine-%s-%d"`, machineID, version)
}

var environmentVariableNamePattern = mustEnvironmentVariableNamePattern()
var environmentVariableErrorCodePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
var environmentVariableDocumentIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func mustEnvironmentVariableNamePattern() *regexp.Regexp {
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
}

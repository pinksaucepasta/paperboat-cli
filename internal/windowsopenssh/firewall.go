package windowsopenssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const firewallStateSchema = "paperboat.windows-openssh-firewall/v1"

var (
	ErrFirewallSnapshot  = errors.New("openssh_firewall_snapshot_failed")
	ErrFirewallOwnership = errors.New("openssh_firewall_ownership_conflict")
)

// FirewallRule is the bounded OpenSSH-relevant firewall state captured before
// and after WinGet. It deliberately omits unrelated rules and all credentials.
type FirewallRule struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	Profiles    string `json:"profiles"`
	Program     string `json:"program"`
	Service     string `json:"service"`
	Protocol    string `json:"protocol"`
	LocalPort   string `json:"local_port"`
}

type FirewallSnapshot struct {
	CapturedAt     time.Time         `json:"captured_at"`
	SystemSSHD     bool              `json:"system_sshd"`
	Profiles       []FirewallProfile `json:"profiles"`
	OpenSSHInbound []FirewallRule    `json:"openssh_inbound"`
}

type FirewallProfile struct {
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	DefaultInboundAction string `json:"default_inbound_action"`
}

type OwnedFirewallRule struct {
	Rule FirewallRule `json:"rule"`
}

// FirewallState is persisted under Paperboat's SSH state. Only entries in
// Owned may be disabled during repair or removed during uninstall.
type FirewallState struct {
	Schema string              `json:"schema"`
	Before FirewallSnapshot    `json:"before"`
	After  FirewallSnapshot    `json:"after"`
	Owned  []OwnedFirewallRule `json:"owned"`
}

func firewallStatePath(config Config) string {
	return filepath.Join(config.StateRoot, "firewall-state.json")
}

func firewallOwnershipPlan(before, after FirewallSnapshot) []OwnedFirewallRule {
	if before.SystemSSHD {
		return nil
	}
	existing := make(map[string]FirewallRule, len(before.OpenSSHInbound))
	for _, rule := range before.OpenSSHInbound {
		existing[strings.ToLower(rule.Name)] = rule
	}
	owned := make([]OwnedFirewallRule, 0, len(after.OpenSSHInbound))
	for _, rule := range after.OpenSSHInbound {
		if _, found := existing[strings.ToLower(rule.Name)]; found || !isOpenSSHPublicInbound(rule) {
			continue
		}
		owned = append(owned, OwnedFirewallRule{Rule: rule})
	}
	slices.SortFunc(owned, func(left, right OwnedFirewallRule) int { return strings.Compare(left.Rule.Name, right.Rule.Name) })
	return owned
}

func isOpenSSHPublicInbound(rule FirewallRule) bool {
	return rule.Enabled && isOpenSSHInboundIdentity(rule) && firewallPublicProfile(rule.Profiles)
}

func isOpenSSHInboundIdentity(rule FirewallRule) bool {
	if strings.TrimSpace(rule.Name) == "" || !strings.EqualFold(rule.Direction, "Inbound") || !strings.EqualFold(rule.Action, "Allow") {
		return false
	}
	program := strings.ToLower(filepath.Base(strings.ReplaceAll(strings.TrimSpace(rule.Program), `\`, `/`)))
	if program != "sshd.exe" {
		return false
	}
	identity := strings.ToLower(rule.Name + " " + rule.DisplayName + " " + rule.Service)
	return strings.Contains(identity, "openssh") || strings.Contains(identity, "sshd")
}

func firewallPublicProfile(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "7" || value == "all" || strings.Contains(value, "public")
}

func sameFirewallRule(left, right FirewallRule) bool {
	return strings.EqualFold(left.Name, right.Name) && strings.EqualFold(left.Direction, right.Direction) && strings.EqualFold(left.Action, right.Action) &&
		strings.EqualFold(filepath.Clean(left.Program), filepath.Clean(right.Program)) && strings.EqualFold(left.Service, right.Service) &&
		strings.EqualFold(left.Protocol, right.Protocol) && strings.EqualFold(left.LocalPort, right.LocalPort)
}

func writeFirewallState(config Config, state FirewallState) error {
	if err := validateFirewallState(state); err != nil {
		return err
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(firewallStatePath(config), body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func readFirewallState(config Config) (FirewallState, bool, error) {
	body, err := os.ReadFile(firewallStatePath(config))
	if errors.Is(err, os.ErrNotExist) {
		return FirewallState{}, false, nil
	}
	if err != nil {
		return FirewallState{}, false, err
	}
	var state FirewallState
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF || validateFirewallState(state) != nil {
		return FirewallState{}, false, ErrFirewallOwnership
	}
	return state, true, nil
}

func validateFirewallState(state FirewallState) error {
	if state.Schema != firewallStateSchema || state.Before.CapturedAt.IsZero() || state.After.CapturedAt.IsZero() {
		return ErrFirewallOwnership
	}
	seen := make(map[string]bool, len(state.Owned))
	for _, owned := range state.Owned {
		if !isOpenSSHPublicInbound(owned.Rule) || seen[strings.ToLower(owned.Rule.Name)] {
			return ErrFirewallOwnership
		}
		seen[strings.ToLower(owned.Rule.Name)] = true
	}
	return nil
}

func persistFirewallOwnership(ctx context.Context, config Config, before, after FirewallSnapshot) error {
	owned := firewallOwnershipPlan(before, after)
	for _, rule := range owned {
		if err := disableOwnedFirewallRule(ctx, config, rule.Rule.Name); err != nil {
			return errors.Join(ErrFirewallSnapshot, err)
		}
	}
	return writeFirewallState(config, FirewallState{Schema: firewallStateSchema, Before: before, After: after, Owned: owned})
}

// RepairFirewallOwnership verifies Paperboat's owned rule set and restores the
// loopback-only posture only for entries recorded at installation time.
func RepairFirewallOwnership(ctx context.Context, config Config) error {
	state, exists, err := readFirewallState(config)
	if err != nil {
		return errors.Join(ErrRepairFailed, err)
	}
	current, err := snapshotFirewall(ctx, config)
	if err != nil {
		return errors.Join(ErrRepairFailed, ErrFirewallSnapshot, err)
	}
	if !exists {
		return writeFirewallState(config, FirewallState{Schema: firewallStateSchema, Before: current, After: current})
	}
	byName := make(map[string]FirewallRule, len(current.OpenSSHInbound))
	for _, rule := range current.OpenSSHInbound {
		byName[strings.ToLower(rule.Name)] = rule
	}
	for _, owned := range state.Owned {
		rule, found := byName[strings.ToLower(owned.Rule.Name)]
		if !found {
			continue
		}
		if !sameFirewallRule(rule, owned.Rule) || !isOpenSSHInboundIdentity(rule) {
			return errors.Join(ErrRepairFailed, ErrFirewallOwnership)
		}
		if rule.Enabled {
			if err := disableOwnedFirewallRule(ctx, config, rule.Name); err != nil {
				return errors.Join(ErrRepairFailed, err)
			}
		}
	}
	return nil
}

func CheckFirewallOwnership(ctx context.Context, config Config) error {
	state, exists, err := readFirewallState(config)
	if err != nil {
		return err
	}
	if !exists {
		return ErrFirewallOwnership
	}
	current, err := snapshotFirewall(ctx, config)
	if err != nil {
		return errors.Join(ErrFirewallSnapshot, err)
	}
	byName := make(map[string]FirewallRule, len(current.OpenSSHInbound))
	for _, rule := range current.OpenSSHInbound {
		byName[strings.ToLower(rule.Name)] = rule
		if paperboatEndpointFirewallRule(rule, config.Port) {
			return ErrFirewallOwnership
		}
	}
	for _, owned := range state.Owned {
		rule, found := byName[strings.ToLower(owned.Rule.Name)]
		if found && (!sameFirewallRule(rule, owned.Rule) || !isOpenSSHInboundIdentity(rule) || rule.Enabled) {
			return ErrFirewallOwnership
		}
	}
	return nil
}

func paperboatEndpointFirewallRule(rule FirewallRule, port uint16) bool {
	if !rule.Enabled || !strings.EqualFold(rule.Direction, "Inbound") || !strings.EqualFold(rule.Action, "Allow") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(rule.Service), ServiceName) || firewallPortContains(rule.LocalPort, port)
}

func firewallPortContains(value string, port uint16) bool {
	want := strconv.Itoa(int(port))
	for _, candidate := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		if strings.TrimSpace(candidate) == want {
			return true
		}
	}
	return false
}

// RemovePaperboatState removes only Paperboat's service, SSH state, and
// recorded firewall deltas. The shared WinGet package and the normal sshd
// service are deliberately outside this ownership boundary.
func RemovePaperboatState(ctx context.Context, config Config) error {
	if err := validate(config); err != nil {
		return err
	}
	var result error
	result = errors.Join(result, RemoveServiceOwned(ctx, config))
	state, exists, stateErr := readFirewallState(config)
	if stateErr != nil {
		result = errors.Join(result, stateErr)
	} else if exists {
		current, snapshotErr := snapshotFirewall(ctx, config)
		if snapshotErr != nil {
			result = errors.Join(result, snapshotErr)
		} else {
			byName := make(map[string]FirewallRule, len(current.OpenSSHInbound))
			for _, rule := range current.OpenSSHInbound {
				byName[strings.ToLower(rule.Name)] = rule
			}
			for _, owned := range state.Owned {
				if rule, found := byName[strings.ToLower(owned.Rule.Name)]; found {
					if !sameFirewallRule(rule, owned.Rule) {
						result = errors.Join(result, ErrFirewallOwnership)
						continue
					}
					result = errors.Join(result, removeOwnedFirewallRule(ctx, config, rule.Name))
				}
			}
		}
	}
	if result != nil {
		return result
	}
	for _, path := range []string{filepath.Join(config.StateRoot, "sshd_config"), filepath.Join(config.StateRoot, "install-state.json"), firewallStatePath(config)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	for _, path := range []string{filepath.Join(config.StateRoot, "hostkeys"), filepath.Join(config.StateRoot, "authorized_keys"), filepath.Join(config.StateRoot, "logs")} {
		if err := os.RemoveAll(path); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type ledger struct {
	Schema                string                       `json:"schema"`
	Authority             authority                    `json:"authority"`
	AllowedFeatureStates  []string                     `json:"allowed_feature_states"`
	AllowedGateStatuses   []string                     `json:"allowed_gate_statuses"`
	EvidenceDimensions    []dimension                  `json:"evidence_dimensions"`
	ApplicabilityProfiles map[string][]string          `json:"applicability_profiles"`
	StateProfiles         map[string]map[string]string `json:"state_profiles"`
	ReleaseTargets        map[string]releaseTarget     `json:"release_targets"`
	Gates                 []gate                       `json:"gates"`
	EvidenceCatalog       []evidence                   `json:"evidence_catalog"`
	Features              []feature                    `json:"features"`
	VerificationCommands  []verificationCommand        `json:"verification_commands"`
}

type authority struct {
	CanonicalData               string   `json:"canonical_data"`
	HumanCompanion              string   `json:"human_companion"`
	AuthorityStatus             string   `json:"authority_status"`
	AuthorityBlockers           []string `json:"authority_blockers"`
	IntentionalFeatureOmissions []string `json:"intentional_feature_omissions"`
}

type dimension struct {
	ID string `json:"id"`
}

type releaseTarget struct {
	TargetStability         string   `json:"target_stability"`
	Channel                 string   `json:"channel"`
	CurrentReadiness        string   `json:"current_readiness"`
	RequiredFeatureState    string   `json:"required_feature_state"`
	NativeTestRequired      bool     `json:"native_test_required"`
	NativeTested            bool     `json:"native_tested"`
	NativeQualificationGate string   `json:"native_qualification_gate"`
	PromotionBlockedUntil   string   `json:"promotion_blocked_until"`
	Blockers                []string `json:"blockers"`
}

type gate struct {
	ID                      string   `json:"id"`
	Status                  string   `json:"status"`
	RequiredFor             []string `json:"required_for"`
	Command                 string   `json:"command"`
	CountsAsNativeExecution bool     `json:"counts_as_native_execution"`
	SkipReason              string   `json:"skip_reason"`
	EvidenceRefs            []string `json:"evidence_refs"`
	Blockers                []string `json:"blockers"`
}

type evidence struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Scope          []string `json:"scope"`
	Status         string   `json:"status"`
	Runner         string   `json:"runner"`
	WindowsEdition string   `json:"windows_edition"`
	WindowsBuild   string   `json:"windows_build"`
	Architecture   string   `json:"architecture"`
	Command        string   `json:"command"`
	Tests          []string `json:"tests"`
}

type feature struct {
	ID                   string   `json:"id"`
	Group                string   `json:"group"`
	Requirement          string   `json:"requirement"`
	EvidenceProfile      string   `json:"evidence_profile"`
	ApplicabilityProfile string   `json:"applicability_profile"`
	ReleaseBlocker       bool     `json:"release_blocker"`
	EvidenceRefs         []string `json:"evidence_refs"`
	Blockers             []string `json:"blockers"`
}

type verificationCommand struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

var expectedDimensions = []string{
	"windows_amd64_client",
	"windows_amd64_host",
	"windows_arm64_compile",
	"windows_arm64_native",
	"windows_to_windows",
	"windows_to_macos",
	"macos_to_windows",
	"windows_to_linux",
	"linux_to_windows",
	"human_ux",
	"json_ux",
	"server_control_plane",
	"dashboard",
	"release_authority",
	"documentation_support",
}

var expectedFeatureStates = []string{
	"not_started",
	"implemented",
	"amd64_native_verified",
	"arm64_cross_verified",
	"arm64_native_verified",
	"stable_ready",
}

var expectedGateStatuses = []string{
	"not_started",
	"in_progress",
	"blocked",
	"blocked_no_hardware",
	"pass",
	"fail",
	"not_applicable",
}

var expectedGateIDs = []string{
	"windows_scope_authority",
	"windows_amd64_cross_build",
	"windows_arm64_cross_build",
	"windows_amd64_native_full_matrix",
	"native_windows_arm64_e2e",
	"windows_arm64_beta_cross_gate",
	"windows_amd64_stable_release",
	"windows_artifact_signing",
}

var expectedFeatureIDs = []string{
	"auth.login", "setup.host", "setup.pair", "setup.unpair", "machine.ownership",
	"terminal.interactive", "terminal.exec", "terminal.sessions", "terminal.replay", "terminal.resize",
	"terminal.cancellation", "terminal.reconnect", "terminal.shells", "terminal.utf8-vt", "terminal.ctrl-c",
	"terminal.descendant-cleanup", "codex.sessions",
	"ssh.provisioning", "ssh.client-server", "ssh.paperboat-service", "ssh.authorized-keys", "ssh.host-keys",
	"ssh.agent", "ssh.key-rotation", "ssh.proxy-command", "ssh.scp", "ssh.sftp", "ssh.firewall", "ssh.repair",
	"transfer.send", "transfer.receive", "transfer.inbox", "transfer.encryption", "transfer.resume", "transfer.cancellation",
	"preview.private", "preview.public", "preview.http", "preview.websocket", "preview.sse", "preview.detached-serve",
	"config.sync", "config.git", "config.chezmoi", "config.restore", "config.flush", "config.conflicts",
	"transport.direct-quic", "transport.relayed-quic", "transport.wss", "transport.network-migration", "transport.sleep-wake",
	"transport.ipv4-ipv6", "transport.pmtu", "transport.vpn-nat-firewall-proxy",
	"local-api.named-pipe", "local-api.acl-token", "local-api.operations", "os.known-folders", "os.acl-reparse",
	"os.long-paths", "os.atomic-replacement", "os.credentials", "os.pe-authenticode", "os.winsock-observer",
	"os.services", "os.owner-token", "os.user-profile", "os.process-tree", "os.conpty", "os.workspace-smb-efs",
	"ops.diagnostics", "ops.bug-reports", "ops.completions", "ops.telemetry", "ops.update", "ops.rollback",
	"ops.repair", "ops.uninstall", "distribution.msi", "distribution.winget", "distribution.zip", "distribution.lifecycle",
	"distribution.arch-mismatch", "release.sbom-provenance-signing", "release.tuf", "release.channels-rollout",
	"server.platform-admission", "server.release-index", "dashboard.beta-status", "docs.support",
	"ci.windows-amd64", "ci.windows-arm64",
}

func main() {
	path := "docs/windows-parity.json"
	if len(os.Args) == 2 {
		path = os.Args[1]
	}
	if len(os.Args) > 2 {
		fail(errors.New("usage: validate-windows-parity [path-to-ledger.json]"))
	}
	if err := validate(path); err != nil {
		fail(err)
	}
	root := filepath.Dir(filepath.Dir(path))
	fmt.Printf("windows parity ledger valid: %d features, %d evidence dimensions, %d gates\n", len(expectedFeatureIDs), len(expectedDimensions), len(expectedGateIDs))
	fmt.Printf("companion validated: %s\n", filepath.Join(root, "docs", "windows-parity.md"))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "windows parity ledger invalid: %v\n", err)
	os.Exit(1)
}

func validate(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var l ledger
	if err := json.Unmarshal(body, &l); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if l.Schema != "paperboat.windows-parity/v1" {
		return fmt.Errorf("schema = %q", l.Schema)
	}
	if l.Authority.CanonicalData != "docs/windows-parity.json" || l.Authority.HumanCompanion != "docs/windows-parity.md" {
		return errors.New("authority paths must point to the JSON ledger and Markdown companion")
	}
	if l.Authority.AuthorityStatus != "user_approved_windows_plan_is_authoritative" || len(l.Authority.AuthorityBlockers) != 0 {
		return errors.New("approved Windows plan must be the unambiguous authority")
	}
	if len(l.Authority.IntentionalFeatureOmissions) != 0 {
		return errors.New("intentional_feature_omissions must be empty")
	}
	if !reflect.DeepEqual(l.AllowedFeatureStates, expectedFeatureStates) {
		return fmt.Errorf("allowed_feature_states = %v, want %v", l.AllowedFeatureStates, expectedFeatureStates)
	}
	if !reflect.DeepEqual(l.AllowedGateStatuses, expectedGateStatuses) {
		return fmt.Errorf("allowed_gate_statuses = %v, want %v", l.AllowedGateStatuses, expectedGateStatuses)
	}

	dimensionSet, err := validateDimensions(l.EvidenceDimensions)
	if err != nil {
		return err
	}
	if err := validateProfiles(l, dimensionSet); err != nil {
		return err
	}
	if err := validateEvidence(l, dimensionSet); err != nil {
		return err
	}
	if err := validateFeatures(l, dimensionSet); err != nil {
		return err
	}
	if err := validateTargets(l); err != nil {
		return err
	}
	if err := validateGates(l); err != nil {
		return err
	}
	if err := validateVerificationCommands(l); err != nil {
		return err
	}
	return validateMarkdown(path, l)
}

func validateDimensions(got []dimension) (map[string]bool, error) {
	if len(got) != len(expectedDimensions) {
		return nil, fmt.Errorf("evidence_dimensions has %d entries, want %d", len(got), len(expectedDimensions))
	}
	set := make(map[string]bool, len(got))
	for _, d := range got {
		if d.ID == "" || set[d.ID] {
			return nil, fmt.Errorf("duplicate or empty evidence dimension %q", d.ID)
		}
		set[d.ID] = true
	}
	if !sameSet(set, expectedDimensions) {
		return nil, fmt.Errorf("evidence dimension IDs = %v, want %v", sortedKeys(set), expectedDimensions)
	}
	return set, nil
}

func validateProfiles(l ledger, dimensions map[string]bool) error {
	if len(l.ApplicabilityProfiles) == 0 || len(l.StateProfiles) == 0 {
		return errors.New("applicability_profiles and state_profiles are required")
	}
	for name, profile := range l.ApplicabilityProfiles {
		seen := map[string]bool{}
		for _, id := range profile {
			if !dimensions[id] {
				return fmt.Errorf("applicability profile %q references unknown dimension %q", name, id)
			}
			if seen[id] {
				return fmt.Errorf("applicability profile %q repeats dimension %q", name, id)
			}
			seen[id] = true
		}
		if len(profile) == 0 {
			return fmt.Errorf("applicability profile %q is empty", name)
		}
	}
	allowed := make(map[string]bool, len(expectedFeatureStates))
	for _, state := range expectedFeatureStates {
		allowed[state] = true
	}
	for name, profile := range l.StateProfiles {
		if len(profile) != len(dimensions) {
			return fmt.Errorf("state profile %q has %d dimensions, want %d", name, len(profile), len(dimensions))
		}
		for id, state := range profile {
			if !dimensions[id] {
				return fmt.Errorf("state profile %q references unknown dimension %q", name, id)
			}
			if !allowed[state] {
				return fmt.Errorf("state profile %q has invalid state %q for %s", name, state, id)
			}
			if state == "arm64_cross_verified" && id != "windows_arm64_compile" {
				return fmt.Errorf("state profile %q assigns arm64_cross_verified outside windows_arm64_compile", name)
			}
			if state == "arm64_native_verified" && id != "windows_arm64_native" {
				return fmt.Errorf("state profile %q assigns arm64_native_verified outside windows_arm64_native", name)
			}
		}
	}
	return nil
}

func validateEvidence(l ledger, dimensions map[string]bool) error {
	known := map[string]bool{}
	for _, item := range l.EvidenceCatalog {
		if item.ID == "" || known[item.ID] {
			return fmt.Errorf("duplicate or empty evidence catalog ID %q", item.ID)
		}
		known[item.ID] = true
		for _, id := range item.Scope {
			if !dimensions[id] {
				return fmt.Errorf("evidence %q references unknown dimension %q", item.ID, id)
			}
		}
		switch item.Kind {
		case "native_test":
			if item.Status != "pass" || item.Runner == "" || item.WindowsEdition == "" || item.WindowsBuild == "" || item.Architecture == "" || item.Command == "" || len(item.Tests) == 0 {
				return fmt.Errorf("native evidence %q lacks immutable runner, Windows build, command, or test details", item.ID)
			}
			if item.Architecture != "amd64" {
				return fmt.Errorf("native evidence %q has architecture %q, want amd64 for the seeded native evidence", item.ID, item.Architecture)
			}
		case "cross_compile":
			if item.Status != "pass" || item.Architecture == "" || item.Command == "" || len(item.Tests) == 0 {
				return fmt.Errorf("cross-compile evidence %q lacks architecture, command, or pass status", item.ID)
			}
			if contains(item.Scope, "windows_arm64_compile") && item.Architecture != "arm64" {
				return fmt.Errorf("ARM64 cross-compile evidence %q has architecture %q", item.ID, item.Architecture)
			}
		}
	}
	return nil
}

func validateFeatures(l ledger, dimensions map[string]bool) error {
	if len(l.Features) != len(expectedFeatureIDs) {
		return fmt.Errorf("features has %d entries, want %d", len(l.Features), len(expectedFeatureIDs))
	}
	expected := make(map[string]bool, len(expectedFeatureIDs))
	for _, id := range expectedFeatureIDs {
		expected[id] = true
	}
	evidenceIDs := make(map[string]bool, len(l.EvidenceCatalog))
	for _, item := range l.EvidenceCatalog {
		evidenceIDs[item.ID] = true
	}
	seen := map[string]bool{}
	armCross := findGate(l.Gates, "windows_arm64_cross_build")
	for _, f := range l.Features {
		if f.ID == "" || seen[f.ID] {
			return fmt.Errorf("duplicate or empty feature ID %q", f.ID)
		}
		if !expected[f.ID] {
			return fmt.Errorf("unexpected feature ID %q", f.ID)
		}
		seen[f.ID] = true
		if f.Group == "" || f.Requirement == "" || f.EvidenceProfile == "" || f.ApplicabilityProfile == "" {
			return fmt.Errorf("feature %q is missing group, requirement, or profile", f.ID)
		}
		applicable, ok := l.ApplicabilityProfiles[f.ApplicabilityProfile]
		if !ok {
			return fmt.Errorf("feature %q references unknown applicability profile %q", f.ID, f.ApplicabilityProfile)
		}
		states, ok := l.StateProfiles[f.EvidenceProfile]
		if !ok {
			return fmt.Errorf("feature %q references unknown evidence profile %q", f.ID, f.EvidenceProfile)
		}
		for _, id := range applicable {
			state, ok := states[id]
			if !ok || state == "" {
				return fmt.Errorf("feature %q has no resolved state for applicable dimension %q", f.ID, id)
			}
			if id == "windows_arm64_native" && state != "not_started" {
				return fmt.Errorf("feature %q claims ARM64 native evidence while native hardware gate is blocked", f.ID)
			}
			if id == "windows_arm64_compile" && state == "arm64_cross_verified" {
				if armCross == nil || armCross.Status != "pass" || !hasFullArm64CrossQualification(l, armCross.EvidenceRefs) {
					return fmt.Errorf("feature %q claims arm64_cross_verified without the full ARM64 package and test-package qualification", f.ID)
				}
			}
		}
		if !f.ReleaseBlocker {
			return fmt.Errorf("feature %q is not marked as a release blocker", f.ID)
		}
		if len(f.Blockers) == 0 {
			return fmt.Errorf("feature %q has no seeded blocker", f.ID)
		}
		for _, ref := range f.EvidenceRefs {
			if !evidenceIDs[ref] {
				return fmt.Errorf("feature %q references unknown evidence %q", f.ID, ref)
			}
		}
	}
	if !sameSet(seen, expectedFeatureIDs) {
		return fmt.Errorf("feature inventory differs from approved plan: got %v", sortedKeys(seen))
	}
	return nil
}

func validateTargets(l ledger) error {
	if len(l.ReleaseTargets) != 2 {
		return fmt.Errorf("release_targets has %d entries, want 2", len(l.ReleaseTargets))
	}
	amd, ok := l.ReleaseTargets["windows/amd64"]
	if !ok {
		return errors.New("missing windows/amd64 release target")
	}
	if amd.TargetStability != "stable" || amd.Channel != "stable" || amd.CurrentReadiness != "blocked" || amd.RequiredFeatureState != "stable_ready" || !amd.NativeTestRequired || amd.NativeTested {
		return fmt.Errorf("windows/amd64 target is not the honest blocked stable seed: %#v", amd)
	}
	arm, ok := l.ReleaseTargets["windows/arm64"]
	if !ok {
		return errors.New("missing windows/arm64 release target")
	}
	if arm.TargetStability != "beta" || arm.Channel != "beta" || !contains([]string{"beta_blocked", "beta_ready"}, arm.CurrentReadiness) || arm.RequiredFeatureState != "arm64_cross_verified" || arm.NativeTestRequired || arm.PromotionBlockedUntil != "arm64_native_verified" {
		return fmt.Errorf("windows/arm64 target is not the honest beta seed: %#v", arm)
	}
	return nil
}

func validateGates(l ledger) error {
	knownEvidence := map[string]bool{}
	for _, item := range l.EvidenceCatalog {
		knownEvidence[item.ID] = true
	}
	knownGates := map[string]bool{}
	for _, g := range l.Gates {
		if g.ID == "" || knownGates[g.ID] {
			return fmt.Errorf("duplicate or empty gate ID %q", g.ID)
		}
		knownGates[g.ID] = true
		if !contains(expectedGateStatuses, g.Status) {
			return fmt.Errorf("gate %q has invalid status %q", g.ID, g.Status)
		}
		for _, ref := range g.EvidenceRefs {
			if !knownEvidence[ref] {
				return fmt.Errorf("gate %q references unknown evidence %q", g.ID, ref)
			}
		}
		if g.Status == "blocked_no_hardware" && (g.CountsAsNativeExecution || g.SkipReason != "blocked_no_hardware" || len(g.EvidenceRefs) != 0) {
			return fmt.Errorf("gate %q violates blocked_no_hardware semantics", g.ID)
		}
	}
	if !sameSet(knownGates, expectedGateIDs) {
		return fmt.Errorf("gate inventory differs from approved plan: got %v", sortedKeys(knownGates))
	}
	amdCross := findGate(l.Gates, "windows_amd64_cross_build")
	armCross := findGate(l.Gates, "windows_arm64_cross_build")
	if amdCross == nil || amdCross.Status != "pass" || armCross == nil || armCross.Status != "pass" {
		return errors.New("full Windows cross-build gates must pass before recording cross-verified evidence")
	}
	if !hasFullArm64CrossQualification(l, armCross.EvidenceRefs) {
		return errors.New("windows_arm64_cross_build requires passing ARM64 evidence for go build ./... and every Windows test package")
	}
	armNative := findGate(l.Gates, "native_windows_arm64_e2e")
	armTarget := l.ReleaseTargets["windows/arm64"]
	if armNative == nil || !contains([]string{"blocked_no_hardware", "pass"}, armNative.Status) {
		return errors.New("native_windows_arm64_e2e must be pass or blocked_no_hardware")
	}
	if armNative.Status == "pass" && (!armTarget.NativeTested || !armNative.CountsAsNativeExecution || len(armNative.EvidenceRefs) == 0) {
		return errors.New("native_windows_arm64_e2e pass requires native ARM64 evidence")
	}
	if armNative.Status == "blocked_no_hardware" && armTarget.NativeTested {
		return errors.New("native_windows_arm64_e2e cannot remain blocked after native evidence")
	}
	armBeta := findGate(l.Gates, "windows_arm64_beta_cross_gate")
	if armBeta == nil || !contains([]string{"blocked", "pass"}, armBeta.Status) || !hasFullArm64CrossQualification(l, armBeta.EvidenceRefs) {
		return errors.New("windows_arm64_beta_cross_gate requires the full ARM64 package and test-package qualification")
	}
	allArm64PathsCrossVerified := allArm64ApplicableFeaturesCrossVerified(l)
	if armBeta.Status == "pass" && !allArm64PathsCrossVerified {
		return errors.New("windows_arm64_beta_cross_gate cannot pass until every ARM64-applicable feature is arm64_cross_verified")
	}
	if armBeta.Status == "blocked" && allArm64PathsCrossVerified {
		return errors.New("windows_arm64_beta_cross_gate is blocked even though every ARM64-applicable feature is cross-verified")
	}
	if armBeta.Status == "blocked" && !strings.Contains(strings.Join(armBeta.Blockers, " "), "arm64_cross_verified") {
		return errors.New("blocked windows_arm64_beta_cross_gate must identify remaining arm64_cross_verified work")
	}
	authorityGate := findGate(l.Gates, "windows_scope_authority")
	if authorityGate == nil || authorityGate.Status != "pass" {
		return errors.New("windows_scope_authority must pass once the approved plan is authoritative")
	}
	for _, command := range l.VerificationCommands {
		if command.ID == "" || command.Command == "" {
			return errors.New("verification commands require non-empty IDs and commands")
		}
	}
	return nil
}

func validateVerificationCommands(l ledger) error {
	commands := map[string]string{}
	for _, command := range l.VerificationCommands {
		if commands[command.ID] != "" {
			return fmt.Errorf("duplicate verification command %q", command.ID)
		}
		commands[command.ID] = command.Command
	}
	if !strings.Contains(commands["cross-build-amd64"], "GOOS=windows GOARCH=amd64 go build ./...") {
		return errors.New("missing exact amd64 cross-build verification command")
	}
	if !strings.Contains(commands["cross-build-arm64"], "GOOS=windows GOARCH=arm64 go build ./...") {
		return errors.New("missing exact arm64 cross-build verification command")
	}
	if !strings.Contains(commands["compile-test-packages-arm64"], "GOOS=windows GOARCH=arm64 go test -c") {
		return errors.New("missing exact ARM64 test-package compilation verification command")
	}
	if commands["validate-ledger"] == "" {
		return errors.New("missing validator verification command")
	}
	return nil
}

// hasFullArm64CrossQualification recognizes only evidence that compiles the complete
// Windows ARM64 source graph and every discovered test package. The corresponding CI
// job also verifies the produced PE machine type. A source review, one package build,
// emulator result, or ordinary go build does not satisfy this contract.
func hasFullArm64CrossQualification(l ledger, refs []string) bool {
	for _, ref := range refs {
		for _, item := range l.EvidenceCatalog {
			if item.ID != ref {
				continue
			}
			if item.Kind != "cross_compile" || item.Status != "pass" || item.Architecture != "arm64" || !contains(item.Scope, "windows_arm64_compile") || len(item.Tests) == 0 {
				continue
			}
			command := item.Command
			if strings.Contains(command, "GOOS=windows") && strings.Contains(command, "GOARCH=arm64") && strings.Contains(command, "go build") && strings.Contains(command, "./...") && strings.Contains(command, "go list ./...") && strings.Contains(command, "go test -c") && strings.Contains(strings.Join(item.Tests, " "), "every Go test package") {
				return true
			}
		}
	}
	return false
}

func allArm64ApplicableFeaturesCrossVerified(l ledger) bool {
	for _, f := range l.Features {
		applicable := l.ApplicabilityProfiles[f.ApplicabilityProfile]
		if !contains(applicable, "windows_arm64_compile") {
			continue
		}
		state := l.StateProfiles[f.EvidenceProfile]["windows_arm64_compile"]
		if state != "arm64_cross_verified" && state != "stable_ready" {
			return false
		}
	}
	return true
}

func validateMarkdown(ledgerPath string, l ledger) error {
	root := filepath.Dir(filepath.Dir(ledgerPath))
	markdownPath := filepath.Join(root, "docs", "windows-parity.md")
	body, err := os.ReadFile(markdownPath)
	if err != nil {
		return fmt.Errorf("read companion %s: %w", markdownPath, err)
	}
	text := string(body)
	for _, id := range expectedDimensions {
		if !strings.Contains(text, "`"+id+"`") {
			return fmt.Errorf("companion is missing evidence dimension %q", id)
		}
	}
	for _, id := range expectedFeatureIDs {
		if !strings.Contains(text, "`"+id+"`") {
			return fmt.Errorf("companion is missing feature %q", id)
		}
	}
	for _, id := range expectedGateIDs {
		if !strings.Contains(text, "`"+id+"`") {
			return fmt.Errorf("companion is missing gate %q", id)
		}
	}
	for _, state := range expectedFeatureStates {
		if !strings.Contains(text, "`"+state+"`") {
			return fmt.Errorf("companion is missing feature state %q", state)
		}
	}
	if !strings.Contains(text, "`blocked_no_hardware`") {
		return errors.New("companion is missing blocked_no_hardware semantics")
	}
	if !strings.Contains(text, "Microsoft.OpenSSH.Preview") || strings.Contains(text, "Add-WindowsCapability") && !strings.Contains(text, "does not use `Add-WindowsCapability`") {
		return errors.New("companion is missing the locked OpenSSH installation policy")
	}
	_ = l
	return nil
}

func findGate(gates []gate, id string) *gate {
	for i := range gates {
		if gates[i].ID == id {
			return &gates[i]
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameSet(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, item := range want {
		if !got[item] {
			return false
		}
	}
	return true
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

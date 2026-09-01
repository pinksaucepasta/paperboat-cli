package environmentmanager

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
)

// These errors are deliberately typed. Callers must be able to distinguish a
// missing destructive confirmation from an inventory/CAS safety failure
// without branching on error text.
var (
	ErrDestructiveResetConfirmationRequired = errors.New("ENV destructive reset confirmation required")
	ErrDestructiveResetInventoryChanged     = errors.New("ENV destructive reset inventory changed")
)

var destructiveResetIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var destructiveResetVariablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validDestructiveResetInventory validates the copy persisted in the pending
// transition journal. The API validator protects the first fetch, but the
// journal is independently untrusted after a crash or manual file tampering.
func validDestructiveResetInventory(scopes []api.EnvironmentScopeMetadata) bool {
	if len(scopes) == 0 || len(scopes) > environmente2ee.MaximumHosts+1 {
		return false
	}
	seenMachines := make(map[string]struct{}, len(scopes))
	previousMachine := ""
	for index, scope := range scopes {
		if scope.ScopeState != "active" && scope.ScopeState != "retired" ||
			scope.Version < 1 || scope.Version > int64(environmente2ee.MaximumContractInteger) ||
			scope.KeyEpoch < 1 || scope.KeyEpoch > int64(environmente2ee.MaximumContractInteger) ||
			scope.Names == nil || len(scope.Names) > environmente2ee.MaximumVariables {
			return false
		}
		if _, err := environmente2ee.ParseDocumentID(scope.ManifestID); err != nil {
			return false
		}
		switch scope.Scope {
		case api.EnvironmentVariableScopeGlobal:
			if index != 0 || scope.MachineID != nil || scope.ScopeState != "active" {
				return false
			}
		case api.EnvironmentVariableScopeMachine:
			if index == 0 || scope.MachineID == nil || !destructiveResetIdentifierPattern.MatchString(*scope.MachineID) || previousMachine >= *scope.MachineID {
				return false
			}
			if _, duplicate := seenMachines[*scope.MachineID]; duplicate {
				return false
			}
			seenMachines[*scope.MachineID] = struct{}{}
			previousMachine = *scope.MachineID
		default:
			return false
		}
		seenNames := make(map[string]struct{}, len(scope.Names))
		for nameIndex, name := range scope.Names {
			if len(name) == 0 || len(name) > environmente2ee.MaximumNameBytes || !destructiveResetVariablePattern.MatchString(name) || nameIndex > 0 && scope.Names[nameIndex-1] >= name {
				return false
			}
			upper := strings.ToUpper(name)
			if _, duplicate := seenNames[upper]; duplicate {
				return false
			}
			seenNames[upper] = struct{}{}
			if strings.HasPrefix(upper, "PAPERBOAT_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
				return false
			}
			switch upper {
			case "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "GOTRACEBACK":
				return false
			}
		}
	}
	return true
}

// destructiveResetStateMatchesInventory ensures the server selected exactly
// the scopes frozen by the client. It intentionally compares only scope
// membership here; metadata equality is checked separately against a fresh
// authenticated inventory response before every network mutation.
func destructiveResetStateMatchesInventory(state api.EnvironmentAuthorityTransitionState, scopes []api.EnvironmentScopeMetadata) bool {
	if !validDestructiveResetInventory(scopes) || state.RequiredScopes == nil || len(state.RequiredScopes) != len(scopes) {
		return false
	}
	expected := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope.Scope == api.EnvironmentVariableScopeGlobal {
			expected = append(expected, "g")
		} else if scope.MachineID != nil {
			expected = append(expected, "m:"+*scope.MachineID)
		} else {
			return false
		}
	}
	// The public preflight deliberately presents global first, while the
	// transition API canonicalizes required scopes by their bytewise scope key.
	// Compare the same set in the server's canonical order so a machine ID such
	// as "alpha" cannot make an otherwise identical reset fail closed.
	sort.Strings(expected)
	for index := range expected {
		if state.RequiredScopes[index] != expected[index] {
			return false
		}
	}
	return true
}

func destructiveResetInventoryEqual(left, right []api.EnvironmentScopeMetadata) bool {
	if !validDestructiveResetInventory(left) || !validDestructiveResetInventory(right) || len(left) != len(right) {
		return false
	}
	for index := range left {
		a, b := left[index], right[index]
		if a.Scope != b.Scope || a.ScopeState != b.ScopeState || a.Version != b.Version || a.KeyEpoch != b.KeyEpoch || a.ManifestID != b.ManifestID {
			return false
		}
		if (a.MachineID == nil) != (b.MachineID == nil) || a.MachineID != nil && *a.MachineID != *b.MachineID {
			return false
		}
		if len(a.Names) != len(b.Names) {
			return false
		}
		for nameIndex := range a.Names {
			if a.Names[nameIndex] != b.Names[nameIndex] {
				return false
			}
		}
	}
	return true
}

func destructiveResetScopeMetadata(scopes []api.EnvironmentScopeMetadata, scopeName string) (api.EnvironmentScopeMetadata, bool) {
	machineID, valid := transitionScopeMachineID(scopeName)
	if !valid {
		return api.EnvironmentScopeMetadata{}, false
	}
	for _, scope := range scopes {
		if scope.Scope == api.EnvironmentVariableScopeGlobal && machineID == "" || scope.Scope == api.EnvironmentVariableScopeMachine && scope.MachineID != nil && *scope.MachineID == machineID {
			return scope, true
		}
	}
	return api.EnvironmentScopeMetadata{}, false
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

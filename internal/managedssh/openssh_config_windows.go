//go:build windows

package managedssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const (
	openSSHIncludeMarker = "paperboat-managed-ssh-include-v1"
	openSSHBeginMarker   = "# BEGIN paperboat-managed-ssh-v1"
	openSSHEndMarker     = "# END paperboat-managed-ssh-v1"
	maxOpenSSHConfigSize = 1 << 20
)

var ErrOpenSSHConfigConflict = errors.New("Paperboat OpenSSH configuration conflicts with existing state")

type OpenSSHConfig struct {
	Home, AliasSuffix, ProxyCommand, KnownHostsCommand, AgentSocket, IdentityFile string
	Targets                                                                       []OpenSSHAliasTarget
	// OwnerUID is retained for the cross-platform API. Windows validates the
	// current token SID instead; numeric POSIX IDs have no security meaning.
	OwnerUID uint32
}
type OpenSSHConfigResult struct{ Changed bool }

type OpenSSHOptionConflict struct {
	Line                       int
	Option, Existing, Required string
}

func (e *OpenSSHOptionConflict) Error() string {
	return fmt.Sprintf("%v: line %d sets %s %q; Paperboat requires %q", ErrOpenSSHConfigConflict, e.Line, e.Option, e.Existing, e.Required)
}
func (e *OpenSSHOptionConflict) Unwrap() error { return ErrOpenSSHConfigConflict }

type openSSHInstallRecord struct {
	Version      int    `json:"version"`
	MainExisted  bool   `json:"main_existed"`
	IncludeChunk string `json:"include_chunk"`
	AliasSuffix  string `json:"alias_suffix"`
	OwnedHash    string `json:"owned_hash"`
}

func InstallOpenSSHConfig(config OpenSSHConfig) (OpenSSHConfigResult, error) {
	directory, sid, unlock, err := openWindowsSSHDirectory(config.Home, true)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer unlock()
	if err := recoverWindowsSSHTransaction(directory, sid); err != nil {
		return OpenSSHConfigResult{}, err
	}
	owned, err := renderOwnedOpenSSHConfig(config)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	main, mainSet, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	existingOwned, ownedSet, err := readWindowsSSHFile(directory, "paperboat_config", sid, true)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	record, recordSet, err := readWindowsSSHRecord(directory, sid)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	if conflict := findOpenSSHOptionConflict(main, config); conflict != nil {
		return OpenSSHConfigResult{}, conflict
	}
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	previousCanonicalOwned := bytes.Replace(owned, []byte("    CanonicalizeHostname yes\n"), nil, 1)
	var nextMain []byte
	var includeChunk string
	if recordSet {
		if !ownedSet || record.Version != 1 || !validRecordedInclude(record.IncludeChunk, includeLine) || !validAliasSuffix(record.AliasSuffix) || (!validOwnedOpenSSHContent(existingOwned, record.AliasSuffix) && !validOwnedOpenSSHContentWithoutCanonical(existingOwned, record.AliasSuffix) && !bytes.Equal(existingOwned, previousCanonicalOwned)) || record.OwnedHash != hashOpenSSHBytes(existingOwned) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		nextMain, includeChunk = main, record.IncludeChunk
	} else {
		if ownedSet || bytes.Contains(main, []byte(openSSHIncludeMarker)) || bytes.Contains(main, []byte(openSSHBeginMarker)) {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		offset := firstOpenSSHBlockOffset(main)
		includeChunk = includeLine
		if offset > 0 && main[offset-1] != '\n' {
			includeChunk = "\n" + includeChunk
		}
		nextMain = append(append(append([]byte(nil), main[:offset]...), includeChunk...), main[offset:]...)
	}
	originalMainExisted := mainSet
	if recordSet {
		originalMainExisted = record.MainExisted
	}
	nextRecord := &openSSHInstallRecord{Version: 1, MainExisted: originalMainExisted, IncludeChunk: includeChunk, AliasSuffix: config.AliasSuffix, OwnedHash: hashOpenSSHBytes(owned)}
	if bytes.Equal(main, nextMain) && bytes.Equal(existingOwned, owned) && recordSet && *record == *nextRecord {
		return OpenSSHConfigResult{}, nil
	}
	if err := writeWindowsSSHTransaction(directory, sid, main, mainSet, existingOwned, ownedSet, record, nextMain, owned, nextRecord); err != nil {
		return OpenSSHConfigResult{}, err
	}
	return OpenSSHConfigResult{Changed: true}, nil
}

func ValidateOpenSSHConfig(config OpenSSHConfig) error {
	directory, sid, unlock, err := openWindowsSSHDirectory(config.Home, false)
	if err != nil {
		return err
	}
	defer unlock()
	expected, err := renderOwnedOpenSSHConfig(config)
	if err != nil {
		return err
	}
	main, mainSet, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil {
		return err
	}
	owned, ownedSet, err := readWindowsSSHFile(directory, "paperboat_config", sid, true)
	if err != nil {
		return err
	}
	record, recordSet, err := readWindowsSSHRecord(directory, sid)
	line := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	if err != nil || !mainSet || !ownedSet || !recordSet || record.Version != 1 || record.AliasSuffix != config.AliasSuffix || !validRecordedInclude(record.IncludeChunk, line) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 || !bytes.Equal(owned, expected) || record.OwnedHash != hashOpenSSHBytes(owned) {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	return findOpenSSHOptionConflict(main, config)
}

func ValidateInstalledOpenSSHConfig(home string, ownerUID uint32, aliasSuffix, agentSocket string) error {
	directory, sid, unlock, err := openWindowsSSHDirectory(home, false)
	if err != nil {
		return err
	}
	defer unlock()
	main, mainSet, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil {
		return err
	}
	owned, ownedSet, err := readWindowsSSHFile(directory, "paperboat_config", sid, true)
	if err != nil {
		return err
	}
	record, recordSet, err := readWindowsSSHRecord(directory, sid)
	line := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	lines := strings.Split(strings.TrimSuffix(string(owned), "\n"), "\n")
	wildcard := ownedWildcardLine(lines, aliasSuffix)
	if err != nil || !mainSet || !ownedSet || !recordSet || record.Version != 1 || record.AliasSuffix != aliasSuffix ||
		!validRecordedInclude(record.IncludeChunk, line) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 ||
		!validOwnedOpenSSHContent(owned, aliasSuffix) || record.OwnedHash != hashOpenSSHBytes(owned) || wildcard < 1 ||
		lines[wildcard+3] != "    IdentityAgent \""+strings.ReplaceAll(agentSocket, "\\", "\\\\")+"\"" ||
		lines[wildcard+4] != "    IdentityFile \""+strings.ReplaceAll(ManagedIdentityPublicKeyPath(home), "\\", "\\\\")+"\"" {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	installed := OpenSSHConfig{
		AliasSuffix:       aliasSuffix,
		ProxyCommand:      strings.TrimPrefix(lines[wildcard+1], "    ProxyCommand "),
		KnownHostsCommand: strings.TrimPrefix(lines[wildcard+2], "    KnownHostsCommand "),
	}
	return findOpenSSHOptionConflict(main, installed)
}

func UninstallOpenSSHConfig(home string, _ uint32) (OpenSSHConfigResult, error) {
	absent, err := windowsOpenSSHStateAbsent(home)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	if absent {
		return OpenSSHConfigResult{}, nil
	}
	directory, sid, unlock, err := openWindowsSSHDirectory(home, true)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer unlock()
	if err := recoverWindowsSSHTransaction(directory, sid); err != nil {
		return OpenSSHConfigResult{}, err
	}
	record, recordSet, err := readWindowsSSHRecord(directory, sid)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	main, mainSet, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	owned, ownedSet, err := readWindowsSSHFile(directory, "paperboat_config", sid, true)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	if !recordSet {
		if ownedSet || bytes.Contains(main, []byte(openSSHIncludeMarker)) || bytes.Contains(main, []byte(openSSHBeginMarker)) {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		return OpenSSHConfigResult{}, nil
	}
	line := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	if !mainSet || !ownedSet || !validRecordedInclude(record.IncludeChunk, line) || !validOwnedOpenSSHContent(owned, record.AliasSuffix) || record.OwnedHash != hashOpenSSHBytes(owned) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 {
		return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
	}
	nextMain := bytes.Replace(main, []byte(record.IncludeChunk), nil, 1)
	nextMainSet := record.MainExisted || len(nextMain) != 0
	if err := writeWindowsSSHTransaction(directory, sid, main, true, owned, true, record, optionalWindowsSSHBytes(nextMain, nextMainSet), nil, nil); err != nil {
		return OpenSSHConfigResult{}, err
	}
	return OpenSSHConfigResult{Changed: true}, nil
}

func windowsOpenSSHStateAbsent(home string) (bool, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return false, ErrOpenSSHConfigConflict
	}
	directory := filepath.Join(home, ".ssh")
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || windowsReparsePoint(directory) {
		return false, errors.Join(ErrOpenSSHConfigConflict, err)
	}
	for _, name := range []string{"paperboat_config", ".paperboat-config-install-v1.json", ".paperboat-config-transaction-v1.json"} {
		_, statErr := os.Lstat(filepath.Join(directory, name))
		if statErr == nil {
			return false, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return false, errors.Join(ErrOpenSSHConfigConflict, statErr)
		}
	}
	main, readErr := os.ReadFile(filepath.Join(directory, "config"))
	if errors.Is(readErr, os.ErrNotExist) {
		return true, nil
	}
	if readErr != nil || bytes.Contains(main, []byte(openSSHIncludeMarker)) || bytes.Contains(main, []byte(openSSHBeginMarker)) || bytes.Contains(main, []byte(openSSHEndMarker)) {
		return false, errors.Join(ErrOpenSSHConfigConflict, readErr)
	}
	return true, nil
}

func optionalWindowsSSHBytes(value []byte, set bool) []byte {
	if set {
		return value
	}
	return nil
}

func renderOwnedOpenSSHConfig(config OpenSSHConfig) ([]byte, error) {
	if !validAliasSuffix(config.AliasSuffix) || !validOpenSSHCommand(config.ProxyCommand) || !validOpenSSHCommand(config.KnownHostsCommand) || !validWindowsAgentPipe(config.AgentSocket) || strings.ContainsAny(config.AgentSocket, "\r\n\x00\"") || !filepath.IsAbs(config.IdentityFile) || strings.ContainsAny(config.IdentityFile, "\r\n\x00\"") {
		return nil, ErrOpenSSHConfigConflict
	}
	var targets strings.Builder
	seen := make(map[string]struct{}, len(config.Targets))
	for _, target := range config.Targets {
		host, err := AliasHost(target.Alias, config.AliasSuffix)
		if err != nil || target.Port == 0 || target.User == "" || strings.TrimSpace(target.User) != target.User || strings.ContainsAny(target.User, " \t\r\n\x00\"") {
			return nil, ErrOpenSSHConfigConflict
		}
		if _, exists := seen[host]; exists {
			return nil, ErrOpenSSHConfigConflict
		}
		seen[host] = struct{}{}
		fmt.Fprintf(&targets, "Host %s\n    User %s\n    Port %d\n", openSSHHostPatterns(host, target.DisplayName, config.AliasSuffix), target.User, target.Port)
	}
	return []byte(openSSHBeginMarker + "\n" + targets.String() + "Host *." + config.AliasSuffix + "\n" + "    ProxyCommand " + config.ProxyCommand + "\n" + "    KnownHostsCommand " + config.KnownHostsCommand + "\n" + "    IdentityAgent \"" + strings.ReplaceAll(config.AgentSocket, "\\", "\\\\") + "\"\n" + "    IdentityFile \"" + strings.ReplaceAll(config.IdentityFile, "\\", "\\\\") + "\"\n" + "    IdentitiesOnly yes\n    BatchMode yes\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    StrictHostKeyChecking yes\n    CheckHostIP no\n    UserKnownHostsFile none\n    GlobalKnownHostsFile none\n    CanonicalizeHostname yes\n" + openSSHEndMarker + "\n"), nil
}

func validRecordedInclude(chunk, line string) bool { return chunk == line || chunk == "\n"+line }
func validOwnedOpenSSHContent(value []byte, suffix string) bool {
	lines := strings.Split(strings.TrimSuffix(string(value), "\n"), "\n")
	wildcard := ownedWildcardLine(lines, suffix)
	if wildcard < 1 || len(lines) != wildcard+15 || lines[0] != openSSHBeginMarker || lines[len(lines)-1] != openSSHEndMarker {
		return false
	}
	for index := 1; index < wildcard; index += 3 {
		if index+2 >= wildcard || !strings.HasPrefix(lines[index], "Host ") || !strings.HasSuffix(lines[index], "."+suffix) || !strings.HasPrefix(lines[index+1], "    User ") || !strings.HasPrefix(lines[index+2], "    Port ") {
			return false
		}
	}
	agent, agentValid := decodeWindowsOpenSSHOption(lines[wildcard+3], "    IdentityAgent ")
	identity, identityValid := decodeWindowsOpenSSHOption(lines[wildcard+4], "    IdentityFile ")
	return strings.HasPrefix(lines[wildcard+1], "    ProxyCommand ") && strings.HasPrefix(lines[wildcard+2], "    KnownHostsCommand ") && agentValid && validWindowsAgentPipe(agent) && identityValid && filepath.IsAbs(identity) && strings.EqualFold(filepath.Base(identity), ManagedIdentityPublicKeyFilename) && strings.EqualFold(filepath.Base(filepath.Dir(identity)), ".ssh") && lines[wildcard+5] == "    IdentitiesOnly yes" && lines[wildcard+6] == "    BatchMode yes" && lines[wildcard+7] == "    PasswordAuthentication no" && lines[wildcard+8] == "    KbdInteractiveAuthentication no" && lines[wildcard+9] == "    StrictHostKeyChecking yes" && lines[wildcard+10] == "    CheckHostIP no" && lines[wildcard+11] == "    UserKnownHostsFile none" && lines[wildcard+12] == "    GlobalKnownHostsFile none" && lines[wildcard+13] == "    CanonicalizeHostname yes"
}

func decodeWindowsOpenSSHOption(line, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix+"\"") || !strings.HasSuffix(line, "\"") {
		return "", false
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(line, prefix+"\""), "\"")
	if encoded == "" || strings.ContainsRune(encoded, '"') {
		return "", false
	}
	decoded := strings.ReplaceAll(encoded, `\\`, `\`)
	return decoded, strings.ReplaceAll(decoded, `\`, `\\`) == encoded
}

func ownedWildcardLine(lines []string, suffix string) int {
	for index, line := range lines {
		if line == "Host *."+suffix && (index-1)%3 == 0 {
			return index
		}
	}
	return -1
}

func validOpenSSHCommand(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00#")
}
func validOwnedOpenSSHContentWithoutCanonical(value []byte, suffix string) bool {
	needle := []byte(openSSHEndMarker + "\n")
	if bytes.Count(value, needle) != 1 {
		return false
	}
	return validOwnedOpenSSHContent(bytes.Replace(value, needle, []byte("    CanonicalizeHostname yes\n"+openSSHEndMarker+"\n"), 1), suffix)
}
func hashOpenSSHBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func firstOpenSSHBlockOffset(value []byte) int {
	offset := 0
	for _, line := range bytes.SplitAfter(value, []byte{'\n'}) {
		fields := strings.Fields(strings.TrimSpace(string(line)))
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "#") && (strings.EqualFold(fields[0], "Host") || strings.EqualFold(fields[0], "Match")) {
			return offset
		}
		offset += len(line)
	}
	return len(value)
}
func findOpenSSHOptionConflict(value []byte, config OpenSSHConfig) error {
	matching, uncertain := false, false
	probe := "paperboat-probe." + config.AliasSuffix
	for index, line := range bytes.Split(value, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "Host"):
			matching, uncertain = hostPatternsMatch(fields[1:], probe), false
			continue
		case strings.EqualFold(fields[0], "Match"):
			matching, uncertain = false, true
			continue
		}
		if !matching && !uncertain {
			continue
		}
		option := strings.ToLower(fields[0])
		if option != "proxycommand" && option != "knownhostscommand" {
			continue
		}
		existing := strings.TrimSpace(trimmed[len(fields[0]):])
		required := config.ProxyCommand
		if option == "knownhostscommand" {
			required = config.KnownHostsCommand
		}
		if existing != required {
			return &OpenSSHOptionConflict{Line: index + 1, Option: fields[0], Existing: existing, Required: required}
		}
	}
	return nil
}
func hostPatternsMatch(patterns []string, host string) bool {
	matched := false
	for _, pattern := range patterns {
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		ok, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(host))
		if err != nil {
			continue
		}
		if ok && negated {
			return false
		}
		matched = matched || ok
	}
	return matched
}

func openWindowsSSHDirectory(home string, create bool) (string, string, func(), error) {
	sid, err := currentManagedSSHSID()
	if err != nil {
		return "", "", func() {}, err
	}
	if !filepath.IsAbs(home) {
		return "", "", func() {}, ErrOpenSSHConfigConflict
	}
	home = filepath.Clean(home)
	if err := verifyCurrentUserProfileRoot(home, sid); err != nil {
		return "", "", func() {}, err
	}
	directory := filepath.Join(home, ".ssh")
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) && create {
		if err := ensureManagedSSHDirectory(directory, sid); err != nil {
			return "", "", func() {}, err
		}
	} else if err != nil {
		return "", "", func() {}, err
	} else if err := verifyCurrentUserOwnedPath(directory, sid, true); err != nil {
		return "", "", func() {}, err
	}
	unlock, err := lockWindowsSSHConfig(directory, sid)
	if err != nil {
		return "", "", func() {}, err
	}
	if create {
		if err := migrateLegacyWindowsManagedSSHState(directory, sid); err != nil {
			unlock()
			return "", "", func() {}, err
		}
	}
	return directory, sid, unlock, nil
}

func lockWindowsSSHConfig(directory, sid string) (func(), error) {
	sum := sha256.Sum256([]byte(strings.ToLower(directory) + "\x00" + sid))
	name, err := windows.UTF16PtrFromString("Local\\PaperboatManagedSSH-" + hex.EncodeToString(sum[:16]))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, err
	}
	state, err := windows.WaitForSingleObject(handle, uint32((30*time.Second)/time.Millisecond))
	if err != nil || state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED {
		windows.CloseHandle(handle)
		return nil, ErrOpenSSHConfigConflict
	}
	return func() { _ = windows.ReleaseMutex(handle); _ = windows.CloseHandle(handle) }, nil
}

func readWindowsSSHFile(directory, name, sid string, owned bool) ([]byte, bool, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, false, ErrOpenSSHConfigConflict
	}
	opened, exists, err := openPinnedWindowsSSHFile(filepath.Join(directory, name), 0)
	if err != nil || !exists {
		return nil, exists, err
	}
	defer opened.Close()
	userSID, err := windows.StringToSid(sid)
	if err != nil || userSID == nil || !userSID.IsValid() {
		return nil, false, ErrOpenSSHConfigConflict
	}
	if owned {
		if !windowssecurity.HandleOwnerMatchesSID(opened.handle, userSID) || !windowssecurity.ProtectedHandleDACLMatches(opened.handle, managedSSHSDDL(sid)) {
			return nil, false, ErrOpenSSHConfigConflict
		}
	} else if !windowssecurity.HandleOwnerMatchesSID(opened.handle, userSID) {
		return nil, false, ErrOpenSSHConfigConflict
	}
	return append([]byte(nil), opened.value...), true, nil
}

func readWindowsSSHRecord(directory, sid string) (*openSSHInstallRecord, bool, error) {
	value, exists, err := readWindowsSSHFile(directory, ".paperboat-config-install-v1.json", sid, true)
	if err != nil || !exists {
		return nil, exists, err
	}
	record, err := parseWindowsSSHRecord(value)
	return record, err == nil, err
}

func parseWindowsSSHRecord(value []byte) (*openSSHInstallRecord, error) {
	var record openSSHInstallRecord
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || record.Version != 1 || record.IncludeChunk == "" {
		return nil, ErrOpenSSHConfigConflict
	}
	return &record, nil
}

type windowsSSHTransaction struct {
	Version         int                   `json:"version"`
	OriginalMain    string                `json:"original_main"`
	OriginalMainSet bool                  `json:"original_main_set"`
	OriginalOwned   string                `json:"original_owned"`
	OriginalOwnSet  bool                  `json:"original_owned_set"`
	OriginalRecord  *openSSHInstallRecord `json:"original_record,omitempty"`
	NextMain        string                `json:"next_main"`
	NextMainSet     bool                  `json:"next_main_set"`
	NextOwned       string                `json:"next_owned"`
	NextOwnedSet    bool                  `json:"next_owned_set"`
	NextRecord      *openSSHInstallRecord `json:"next_record,omitempty"`
}

func encodeWindowsSSHBytes(value []byte) string { return hex.EncodeToString(value) }
func decodeWindowsSSHBytes(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	valueBytes, err := hex.DecodeString(value)
	if err != nil || len(valueBytes) > maxOpenSSHConfigSize {
		return nil, ErrOpenSSHConfigConflict
	}
	return valueBytes, nil
}
func writeWindowsSSHTransaction(directory, sid string, originalMain []byte, originalMainSet bool, originalOwned []byte, originalOwnedSet bool, originalRecord *openSSHInstallRecord, nextMain []byte, nextOwned []byte, nextRecord *openSSHInstallRecord) error {
	transaction := windowsSSHTransaction{Version: 1, OriginalMain: encodeWindowsSSHBytes(originalMain), OriginalMainSet: originalMainSet, OriginalOwned: encodeWindowsSSHBytes(originalOwned), OriginalOwnSet: originalOwnedSet, OriginalRecord: originalRecord, NextMain: encodeWindowsSSHBytes(nextMain), NextMainSet: nextMain != nil, NextOwned: encodeWindowsSSHBytes(nextOwned), NextOwnedSet: nextOwned != nil, NextRecord: nextRecord}
	journal, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	if err := writeWindowsOwnedSSHFile(directory, ".paperboat-config-transaction-v1.json", sid, append(journal, '\n')); err != nil {
		return err
	}
	if err := publishWindowsSSHState(directory, sid, transaction.NextMain, transaction.NextMainSet, transaction.NextOwned, transaction.NextOwnedSet, transaction.NextRecord); err != nil {
		rollbackErr := publishWindowsSSHState(directory, sid, transaction.OriginalMain, transaction.OriginalMainSet, transaction.OriginalOwned, transaction.OriginalOwnSet, transaction.OriginalRecord)
		return errors.Join(err, rollbackErr)
	}
	return removeWindowsOwnedSSHFile(directory, ".paperboat-config-transaction-v1.json", sid)
}
func recoverWindowsSSHTransaction(directory, sid string) error {
	value, exists, err := readWindowsSSHFile(directory, ".paperboat-config-transaction-v1.json", sid, true)
	if err != nil || !exists {
		return err
	}
	var transaction windowsSSHTransaction
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transaction); err != nil || decoder.Decode(&struct{}{}) != io.EOF || transaction.Version != 1 {
		return ErrOpenSSHConfigConflict
	}
	if err := publishWindowsSSHState(directory, sid, transaction.OriginalMain, transaction.OriginalMainSet, transaction.OriginalOwned, transaction.OriginalOwnSet, transaction.OriginalRecord); err != nil {
		return err
	}
	return removeWindowsOwnedSSHFile(directory, ".paperboat-config-transaction-v1.json", sid)
}
func publishWindowsSSHState(directory, sid, main string, mainSet bool, owned string, ownedSet bool, record *openSSHInstallRecord) error {
	if ownedSet {
		value, err := decodeWindowsSSHBytes(owned)
		if err != nil {
			return err
		}
		if err := writeWindowsOwnedSSHFile(directory, "paperboat_config", sid, value); err != nil {
			return err
		}
	} else if err := removeWindowsOwnedSSHFile(directory, "paperboat_config", sid); err != nil {
		return err
	}
	if mainSet {
		value, err := decodeWindowsSSHBytes(main)
		if err != nil {
			return err
		}
		if err := writeWindowsUserSSHConfig(directory, sid, value); err != nil {
			return err
		}
	} else if err := removeWindowsUserSSHConfig(directory, sid); err != nil {
		return err
	}
	if record == nil {
		return removeWindowsOwnedSSHFile(directory, ".paperboat-config-install-v1.json", sid)
	}
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeWindowsOwnedSSHFile(directory, ".paperboat-config-install-v1.json", sid, append(value, '\n'))
}
func writeWindowsOwnedSSHFile(directory, name, sid string, value []byte) error {
	path := filepath.Join(directory, name)
	if err := withManagedSSHOwner(sid, func() error {
		return atomicfile.Write(path, value, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: managedSSHSDDL(sid)})
	}); err != nil {
		return err
	}
	opened, exists, err := openPinnedWindowsSSHFile(path, 0)
	if err != nil || !exists || opened == nil {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	defer opened.Close()
	userSID, err := windows.StringToSid(sid)
	if err != nil || userSID == nil || !windowssecurity.HandleOwnerMatchesSID(opened.handle, userSID) || !windowssecurity.ProtectedHandleDACLMatches(opened.handle, managedSSHSDDL(sid)) || !bytes.Equal(opened.value, value) {
		return ErrOpenSSHConfigConflict
	}
	return nil
}
func removeWindowsOwnedSSHFile(directory, name, sid string) error {
	path := filepath.Join(directory, name)
	if _, exists, err := readWindowsSSHFile(directory, name, sid, true); err != nil {
		return err
	} else if !exists {
		return nil
	}
	return os.Remove(path)
}
func writeWindowsUserSSHConfig(directory, sid string, value []byte) error {
	path := filepath.Join(directory, "config")
	existed := false
	if _, exists, err := readWindowsSSHFile(directory, "config", sid, false); err != nil {
		return err
	} else {
		existed = exists
	}
	if !existed {
		return writeWindowsOwnedSSHFile(directory, "config", sid, value)
	}
	return withManagedSSHOwner(sid, func() error {
		return replaceWindowsUserSSHFile(directory, path, sid, value)
	})
}

func replaceWindowsUserSSHFile(directory, path, sid string, value []byte) error {
	//paperboat:allow-source-policy atomic-replacement owner=managed-ssh-windows reason=same-directory-acl-protected-config-staging
	temporary, err := os.CreateTemp(directory, ".paperboat-config-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := copyWindowsFileSecurity(path, temporaryPath); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	verified, exists, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil || !exists || !bytes.Equal(verified, value) {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	return nil
}
func removeWindowsUserSSHConfig(directory, sid string) error {
	path := filepath.Join(directory, "config")
	_, exists, err := readWindowsSSHFile(directory, "config", sid, false)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return os.Remove(path)
}
func copyWindowsFileSecurity(source, destination string) error {
	descriptor, err := windows.GetNamedSecurityInfo(source, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(destination, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, owner, group, dacl, nil)
}

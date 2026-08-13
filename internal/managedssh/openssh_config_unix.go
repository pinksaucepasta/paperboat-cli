//go:build darwin || linux

package managedssh

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	openSSHIncludeMarker = "paperboat-managed-ssh-include-v1"
	openSSHBeginMarker   = "# BEGIN paperboat-managed-ssh-v1"
	openSSHEndMarker     = "# END paperboat-managed-ssh-v1"
	maxOpenSSHConfigSize = 1 << 20
)

var ErrOpenSSHConfigConflict = errors.New("Paperboat OpenSSH configuration conflicts with existing state")

type OpenSSHConfig struct {
	Home              string
	OwnerUID          uint32
	AliasSuffix       string
	ProxyCommand      string
	KnownHostsCommand string
	AgentSocket       string
}

type OpenSSHConfigResult struct{ Changed bool }

// ValidateOpenSSHConfig verifies the exact installed Paperboat state without
// repairing, creating, or otherwise mutating any SSH configuration file.
func ValidateOpenSSHConfig(config OpenSSHConfig) error {
	directoryFD, closeDirectory, err := openExistingOpenSSHConfigDirectory(config.Home, config.OwnerUID)
	if err != nil {
		return err
	}
	defer closeDirectory()
	expectedOwned, err := renderOwnedOpenSSHConfig(config)
	if err != nil {
		return err
	}
	main, mainSet, err := readOpenSSHFileAt(directoryFD, "config", config.OwnerUID)
	if err != nil {
		return err
	}
	owned, ownedSet, err := readOpenSSHFileAt(directoryFD, "paperboat_config", config.OwnerUID)
	if err != nil {
		return err
	}
	record, recordSet, err := readOpenSSHRecord(directoryFD, config.OwnerUID)
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	if err != nil || !mainSet || !ownedSet || !recordSet || record.Version != 1 || record.AliasSuffix != config.AliasSuffix || !validRecordedInclude(record.IncludeChunk, includeLine) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 || !bytes.Equal(owned, expectedOwned) || record.OwnedHash != hashOpenSSHBytes(owned) {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	return findOpenSSHOptionConflict(main, config)
}

// ValidateInstalledOpenSSHConfig validates the daemon-installed fragment
// without assuming the doctor command was invoked through the same executable
// pathname. Updates and package layouts may expose the same installed binary at
// more than one absolute path while OpenSSH intentionally retains one stable
// daemon-managed entry point.
func ValidateInstalledOpenSSHConfig(home string, ownerUID uint32, aliasSuffix, agentSocket string) error {
	directoryFD, closeDirectory, err := openExistingOpenSSHConfigDirectory(home, ownerUID)
	if err != nil {
		return err
	}
	defer closeDirectory()
	main, mainSet, err := readOpenSSHFileAt(directoryFD, "config", ownerUID)
	if err != nil {
		return err
	}
	owned, ownedSet, err := readOpenSSHFileAt(directoryFD, "paperboat_config", ownerUID)
	if err != nil {
		return err
	}
	record, recordSet, err := readOpenSSHRecord(directoryFD, ownerUID)
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	lines := strings.Split(strings.TrimSuffix(string(owned), "\n"), "\n")
	if err != nil || !mainSet || !ownedSet || !recordSet || record.Version != 1 || record.AliasSuffix != aliasSuffix ||
		!validRecordedInclude(record.IncludeChunk, includeLine) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 ||
		!validOwnedOpenSSHContent(owned, aliasSuffix) || record.OwnedHash != hashOpenSSHBytes(owned) || len(lines) != 10 ||
		lines[4] != "    IdentityAgent \""+strings.ReplaceAll(agentSocket, "\\", "\\\\")+"\"" {
		return errors.Join(ErrOpenSSHConfigConflict, err)
	}
	installed := OpenSSHConfig{
		AliasSuffix:       aliasSuffix,
		ProxyCommand:      strings.TrimPrefix(lines[2], "    ProxyCommand "),
		KnownHostsCommand: strings.TrimPrefix(lines[3], "    KnownHostsCommand "),
	}
	return findOpenSSHOptionConflict(main, installed)
}

func openExistingOpenSSHConfigDirectory(home string, ownerUID uint32) (int, func(), error) {
	if !filepath.IsAbs(home) {
		return -1, func() {}, ErrOpenSSHConfigConflict
	}
	home = filepath.Clean(home)
	if err := validateOwnedDirectory(home, ownerUID, false); err != nil {
		return -1, func() {}, err
	}
	directory := filepath.Join(home, ".ssh")
	if err := validateOwnedDirectory(directory, ownerUID, true); err != nil {
		return -1, func() {}, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, func() {}, err
	}
	return fd, func() { _ = unix.Close(fd) }, nil
}

type OpenSSHOptionConflict struct {
	Line     int
	Option   string
	Existing string
	Required string
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

type openSSHTransaction struct {
	Version         int                   `json:"version"`
	OriginalMain    string                `json:"original_main"`
	OriginalMainSet bool                  `json:"original_main_set"`
	OriginalOwned   string                `json:"original_owned"`
	OriginalOwnSet  bool                  `json:"original_owned_set"`
	NextMain        string                `json:"next_main"`
	NextMainSet     bool                  `json:"next_main_set"`
	NextOwned       string                `json:"next_owned"`
	NextOwnedSet    bool                  `json:"next_owned_set"`
	OriginalRecord  *openSSHInstallRecord `json:"original_record,omitempty"`
	NextRecord      *openSSHInstallRecord `json:"next_record,omitempty"`
}

func InstallOpenSSHConfig(config OpenSSHConfig) (OpenSSHConfigResult, error) {
	directoryFD, closeDirectory, err := openSSHConfigDirectory(config.Home, config.OwnerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer closeDirectory()
	unlock, err := lockOpenSSHConfig(directoryFD, config.OwnerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer unlock()
	if err := recoverOpenSSHTransaction(directoryFD, config.OwnerUID); err != nil {
		return OpenSSHConfigResult{}, err
	}
	owned, err := renderOwnedOpenSSHConfig(config)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	main, mainSet, err := readOpenSSHFileAt(directoryFD, "config", config.OwnerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	existingOwned, ownedSet, err := readOpenSSHFileAt(directoryFD, "paperboat_config", config.OwnerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	record, recordSet, err := readOpenSSHRecord(directoryFD, config.OwnerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	if conflict := findOpenSSHOptionConflict(main, config); conflict != nil {
		return OpenSSHConfigResult{}, conflict
	}
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	var nextMain []byte
	var includeChunk string
	if recordSet {
		if !ownedSet || record.Version != 1 || !validRecordedInclude(record.IncludeChunk, includeLine) || !validAliasSuffix(record.AliasSuffix) || !validOwnedOpenSSHContent(existingOwned, record.AliasSuffix) || record.OwnedHash != hashOpenSSHBytes(existingOwned) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		nextMain, includeChunk = main, record.IncludeChunk
	} else {
		if ownedSet || bytes.Contains(main, []byte(openSSHIncludeMarker)) || bytes.Contains(main, []byte(openSSHBeginMarker)) {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		offset := firstOpenSSHBlockOffset(main)
		chunk := includeLine
		if offset > 0 && main[offset-1] != '\n' {
			chunk = "\n" + chunk
		}
		nextMain = make([]byte, 0, len(main)+len(chunk))
		nextMain = append(nextMain, main[:offset]...)
		nextMain = append(nextMain, chunk...)
		nextMain = append(nextMain, main[offset:]...)
		includeChunk = chunk
	}
	originalMainExisted := mainSet
	if recordSet {
		originalMainExisted = record.MainExisted
	}
	nextRecord := &openSSHInstallRecord{Version: 1, MainExisted: originalMainExisted, IncludeChunk: includeChunk, AliasSuffix: config.AliasSuffix, OwnedHash: hashOpenSSHBytes(owned)}
	if bytes.Equal(main, nextMain) && bytes.Equal(existingOwned, owned) && recordSet && *record == *nextRecord {
		return OpenSSHConfigResult{}, nil
	}
	transaction := openSSHTransaction{
		Version: 1, OriginalMain: encodeOpenSSHBytes(main), OriginalMainSet: mainSet,
		OriginalOwned: encodeOpenSSHBytes(existingOwned), OriginalOwnSet: ownedSet,
		OriginalRecord: record,
		NextMain:       encodeOpenSSHBytes(nextMain), NextMainSet: true,
		NextOwned: encodeOpenSSHBytes(owned), NextOwnedSet: true, NextRecord: nextRecord,
	}
	if err := applyOpenSSHTransaction(directoryFD, config.OwnerUID, transaction); err != nil {
		return OpenSSHConfigResult{}, err
	}
	return OpenSSHConfigResult{Changed: true}, nil
}

func UninstallOpenSSHConfig(home string, ownerUID uint32) (OpenSSHConfigResult, error) {
	directoryFD, closeDirectory, err := openSSHConfigDirectory(home, ownerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer closeDirectory()
	unlock, err := lockOpenSSHConfig(directoryFD, ownerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	defer unlock()
	if err := recoverOpenSSHTransaction(directoryFD, ownerUID); err != nil {
		return OpenSSHConfigResult{}, err
	}
	record, recordSet, err := readOpenSSHRecord(directoryFD, ownerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	if !recordSet {
		main, _, mainErr := readOpenSSHFileAt(directoryFD, "config", ownerUID)
		_, ownedSet, ownedErr := readOpenSSHFileAt(directoryFD, "paperboat_config", ownerUID)
		if mainErr != nil || ownedErr != nil {
			return OpenSSHConfigResult{}, errors.Join(mainErr, ownedErr)
		}
		if ownedSet || bytes.Contains(main, []byte(openSSHIncludeMarker)) || bytes.Contains(main, []byte(openSSHBeginMarker)) {
			return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
		}
		return OpenSSHConfigResult{}, nil
	}
	main, mainSet, err := readOpenSSHFileAt(directoryFD, "config", ownerUID)
	if err != nil {
		return OpenSSHConfigResult{}, err
	}
	owned, ownedSet, err := readOpenSSHFileAt(directoryFD, "paperboat_config", ownerUID)
	includeLine := "Include ~/.ssh/paperboat_config # " + openSSHIncludeMarker + "\n"
	if err != nil || !mainSet || !ownedSet || !validRecordedInclude(record.IncludeChunk, includeLine) || !validOwnedOpenSSHContent(owned, record.AliasSuffix) || record.OwnedHash != hashOpenSSHBytes(owned) || bytes.Count(main, []byte(record.IncludeChunk)) != 1 {
		return OpenSSHConfigResult{}, ErrOpenSSHConfigConflict
	}
	nextMain := bytes.Replace(main, []byte(record.IncludeChunk), nil, 1)
	nextMainSet := record.MainExisted || len(nextMain) != 0
	transaction := openSSHTransaction{
		Version: 1, OriginalMain: encodeOpenSSHBytes(main), OriginalMainSet: true,
		OriginalOwned: encodeOpenSSHBytes(owned), OriginalOwnSet: true,
		OriginalRecord: record,
		NextMain:       encodeOpenSSHBytes(nextMain), NextMainSet: nextMainSet,
		NextOwnedSet: false, NextRecord: nil,
	}
	if err := applyOpenSSHTransaction(directoryFD, ownerUID, transaction); err != nil {
		return OpenSSHConfigResult{}, err
	}
	return OpenSSHConfigResult{Changed: true}, nil
}

func renderOwnedOpenSSHConfig(config OpenSSHConfig) ([]byte, error) {
	if !validAliasSuffix(config.AliasSuffix) || !validOpenSSHCommand(config.ProxyCommand) || !validOpenSSHCommand(config.KnownHostsCommand) || !filepath.IsAbs(config.AgentSocket) || strings.ContainsAny(config.AgentSocket, "\r\n\x00\"") {
		return nil, ErrOpenSSHConfigConflict
	}
	content := openSSHBeginMarker + "\n" +
		"Host *." + config.AliasSuffix + "\n" +
		"    ProxyCommand " + config.ProxyCommand + "\n" +
		"    KnownHostsCommand " + config.KnownHostsCommand + "\n" +
		"    IdentityAgent \"" + strings.ReplaceAll(config.AgentSocket, "\\", "\\\\") + "\"\n" +
		"    StrictHostKeyChecking yes\n" +
		"    CheckHostIP no\n" +
		"    UserKnownHostsFile none\n" +
		"    GlobalKnownHostsFile none\n" + openSSHEndMarker + "\n"
	return []byte(content), nil
}

func validRecordedInclude(chunk, line string) bool {
	return chunk == line || chunk == "\n"+line
}

func validOwnedOpenSSHContent(value []byte, suffix string) bool {
	lines := strings.Split(strings.TrimSuffix(string(value), "\n"), "\n")
	if len(lines) != 10 || lines[0] != openSSHBeginMarker || lines[1] != "Host *."+suffix || lines[9] != openSSHEndMarker {
		return false
	}
	requiredPrefixes := []string{"    ProxyCommand ", "    KnownHostsCommand ", "    IdentityAgent \""}
	for index, prefix := range requiredPrefixes {
		if !strings.HasPrefix(lines[index+2], prefix) || len(lines[index+2]) == len(prefix) {
			return false
		}
	}
	return strings.HasSuffix(lines[4], "\"") && lines[5] == "    StrictHostKeyChecking yes" && lines[6] == "    CheckHostIP no" && lines[7] == "    UserKnownHostsFile none" && lines[8] == "    GlobalKnownHostsFile none"
}

func validOpenSSHCommand(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00#")
}

func firstOpenSSHBlockOffset(value []byte) int {
	offset := 0
	for _, line := range bytes.SplitAfter(value, []byte{'\n'}) {
		trimmed := strings.TrimSpace(string(line))
		fields := strings.Fields(trimmed)
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

func openSSHConfigDirectory(home string, ownerUID uint32) (int, func(), error) {
	if !filepath.IsAbs(home) {
		return -1, func() {}, ErrOpenSSHConfigConflict
	}
	home = filepath.Clean(home)
	if err := validateOwnedDirectory(home, ownerUID, false); err != nil {
		return -1, func() {}, err
	}
	directory := filepath.Join(home, ".ssh")
	created := false
	if err := os.Mkdir(directory, 0o700); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return -1, func() {}, err
	}
	if created {
		if err := os.Chown(directory, int(ownerUID), -1); err != nil {
			return -1, func() {}, err
		}
	}
	if err := validateOwnedDirectory(directory, ownerUID, true); err != nil {
		return -1, func() {}, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, func() {}, err
	}
	return fd, func() { _ = unix.Close(fd) }, nil
}

func lockOpenSSHConfig(directoryFD int, ownerUID uint32) (func(), error) {
	fd, created, err := openNamedLock(directoryFD, ".paperboat-config.lock")
	if err != nil {
		return func() {}, err
	}
	if created {
		if err := unix.Fchown(fd, int(ownerUID), -1); err != nil {
			_ = unix.Close(fd)
			return func() {}, err
		}
		_ = unix.Fchmod(fd, 0o600)
	}
	if err := secureOwnedFileDescriptor(fd, ownerUID); err != nil {
		_ = unix.Close(fd)
		return func() {}, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = unix.Close(fd)
		return func() {}, err
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }, nil
}

func openNamedLock(directoryFD int, name string) (int, bool, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		return fd, true, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return -1, false, err
	}
	fd, err = unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	return fd, false, err
}

func readOpenSSHFileAt(directoryFD int, name string, ownerUID uint32) ([]byte, bool, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := secureOwnedFileDescriptor(fd, ownerUID); err != nil {
		return nil, false, err
	}
	value, err := io.ReadAll(io.LimitReader(file, maxOpenSSHConfigSize+1))
	if err != nil || len(value) > maxOpenSSHConfigSize || bytes.IndexByte(value, 0) >= 0 {
		return nil, false, errors.Join(ErrOpenSSHConfigConflict, err)
	}
	return value, true, nil
}

func readOpenSSHRecord(directoryFD int, ownerUID uint32) (*openSSHInstallRecord, bool, error) {
	value, exists, err := readOpenSSHFileAt(directoryFD, ".paperboat-config-install-v1.json", ownerUID)
	if err != nil || !exists {
		return nil, exists, err
	}
	var record openSSHInstallRecord
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || record.Version != 1 || record.IncludeChunk == "" {
		return nil, false, ErrOpenSSHConfigConflict
	}
	return &record, true, nil
}

func applyOpenSSHTransaction(directoryFD int, ownerUID uint32, transaction openSSHTransaction) error {
	journal, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	if err := writeOpenSSHFileAt(directoryFD, ".paperboat-config-transaction-v1.json", ownerUID, append(journal, '\n')); err != nil {
		return err
	}
	if err := publishOpenSSHState(directoryFD, ownerUID, transaction.NextMain, transaction.NextMainSet, transaction.NextOwned, transaction.NextOwnedSet, transaction.NextRecord); err != nil {
		rollbackErr := publishOpenSSHState(directoryFD, ownerUID, transaction.OriginalMain, transaction.OriginalMainSet, transaction.OriginalOwned, transaction.OriginalOwnSet, transaction.OriginalRecord)
		return errors.Join(err, rollbackErr)
	}
	if err := unlinkOpenSSHAt(directoryFD, ".paperboat-config-transaction-v1.json"); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func recoverOpenSSHTransaction(directoryFD int, ownerUID uint32) error {
	value, exists, err := readOpenSSHFileAt(directoryFD, ".paperboat-config-transaction-v1.json", ownerUID)
	if err != nil || !exists {
		return err
	}
	var transaction openSSHTransaction
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transaction); err != nil || decoder.Decode(&struct{}{}) != io.EOF || transaction.Version != 1 {
		return ErrOpenSSHConfigConflict
	}
	if err := publishOpenSSHState(directoryFD, ownerUID, transaction.OriginalMain, transaction.OriginalMainSet, transaction.OriginalOwned, transaction.OriginalOwnSet, transaction.OriginalRecord); err != nil {
		return err
	}
	return unlinkOpenSSHAt(directoryFD, ".paperboat-config-transaction-v1.json")
}

func publishOpenSSHState(directoryFD int, ownerUID uint32, main string, mainSet bool, owned string, ownedSet bool, record *openSSHInstallRecord) error {
	for _, item := range []struct {
		name, value string
		set         bool
	}{{"paperboat_config", owned, ownedSet}, {"config", main, mainSet}} {
		if item.set {
			decoded, err := decodeOpenSSHBytes(item.value)
			if err != nil {
				return err
			}
			if err := writeOpenSSHFileAt(directoryFD, item.name, ownerUID, decoded); err != nil {
				return err
			}
		} else if err := unlinkOpenSSHAt(directoryFD, item.name); err != nil {
			return err
		}
	}
	if record == nil {
		return unlinkOpenSSHAt(directoryFD, ".paperboat-config-install-v1.json")
	}
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeOpenSSHFileAt(directoryFD, ".paperboat-config-install-v1.json", ownerUID, append(value, '\n'))
}

func writeOpenSSHFileAt(directoryFD int, name string, ownerUID uint32, value []byte) error {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".paperboat-config-tmp-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if err := unix.Fchown(fd, int(ownerUID), -1); err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(directoryFD, temporary, directoryFD, name); err != nil {
		return err
	}
	cleanup = false
	return unix.Fsync(directoryFD)
}

func unlinkOpenSSHAt(directoryFD int, name string) error {
	err := unix.Unlinkat(directoryFD, name, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func encodeOpenSSHBytes(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }
func decodeOpenSSHBytes(value string) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(decoded) > maxOpenSSHConfigSize {
		return nil, ErrOpenSSHConfigConflict
	}
	return decoded, nil
}

func hashOpenSSHBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

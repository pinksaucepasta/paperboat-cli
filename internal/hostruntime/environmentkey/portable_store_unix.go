//go:build darwin || linux

package environmentkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const (
	portableEnvelopeSchema = "paperboat.environment-host-sealed/v1"
	portableStateSchema    = "paperboat.environment-host-sealed-state/v1"
	portableWrapDomain     = "paperboat-environment-host-sealed-key-v1\x00"
	portableMaxFileSize    = 128 * 1024
	portableMaxValueSize   = 16 * 1024
	portableMaxReference   = 256
)

type portableStore struct {
	path       string
	lockPath   string
	machineID  string
	generation uint64
	wrapping   [32]byte
	random     io.Reader
}

type portableEnvelope struct {
	Schema     string `json:"schema"`
	MachineID  string `json:"machine_id"`
	Generation uint64 `json:"generation"`
	Nonce      string `json:"nonce_base64url"`
	Ciphertext string `json:"ciphertext_base64url"`
}

type portableState struct {
	Schema     string            `json:"schema"`
	MachineID  string            `json:"machine_id"`
	Generation uint64            `json:"generation"`
	Values     map[string]string `json:"values"`
}

func newPortableStore(config PortableConfig, wrapping [32]byte) (SecretStore, error) {
	if err := preparePortableDirectories(config.StateRoot); err != nil {
		return nil, err
	}
	directory := filepath.Join(filepath.Clean(config.StateRoot), "environment")
	return &portableStore{
		path:       filepath.Join(directory, filepath.Base(PortableCredentialPath)),
		lockPath:   filepath.Join(directory, filepath.Base(PortableCredentialPath)+".lock"),
		machineID:  config.MachineID,
		generation: config.Generation,
		wrapping:   wrapping,
		random:     config.Random,
	}, nil
}

func (s *portableStore) EnvironmentSecureStore() {}

func (s *portableStore) LockEnvironmentHostKey(machineID string, generation uint64) (func() error, error) {
	if s == nil || machineID != s.machineID || generation != s.generation {
		return nil, ErrInvalid
	}
	return lockPortablePath(s.lockPath)
}

func (s *portableStore) Get(reference string) (string, error) {
	if err := validatePortableReference(reference); err != nil {
		return "", err
	}
	state, err := s.load()
	if err != nil {
		return "", err
	}
	value, ok := state.Values[reference]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (s *portableStore) Set(reference, value string) error {
	if err := validatePortableReference(reference); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > portableMaxValueSize || strings.ContainsRune(value, '\x00') {
		return ErrInvalid
	}
	state, err := s.load()
	if errors.Is(err, ErrSecretNotFound) {
		state = portableState{
			Schema: portableStateSchema, MachineID: s.machineID,
			Generation: s.generation, Values: make(map[string]string),
		}
	} else if err != nil {
		return err
	}
	state.Values[reference] = value
	return s.write(state)
}

func (s *portableStore) Delete(reference string) error {
	if err := validatePortableReference(reference); err != nil {
		return err
	}
	state, err := s.load()
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok := state.Values[reference]; !ok {
		return nil
	}
	delete(state.Values, reference)
	return s.write(state)
}

func (s *portableStore) load() (portableState, error) {
	if s == nil || isZeroKey(s.wrapping) || !validIdentity(s.machineID) || s.generation == 0 {
		return portableState{}, ErrInvalid
	}
	file, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return portableState{}, ErrSecretNotFound
	}
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return portableState{}, ErrInvalid
		}
		return portableState{}, errors.Join(ErrUnavailable, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return portableState{}, errors.Join(ErrUnavailable, err)
	}
	if !securePortableFile(info) || info.Size() < 1 || info.Size() > portableMaxFileSize {
		return portableState{}, ErrInvalid
	}
	encoded, err := io.ReadAll(io.LimitReader(file, portableMaxFileSize+1))
	if len(encoded) > portableMaxFileSize {
		clear(encoded)
		return portableState{}, ErrInvalid
	}
	if err != nil {
		clear(encoded)
		return portableState{}, errors.Join(ErrUnavailable, err)
	}
	defer clear(encoded)
	envelope, err := decodePortableEnvelope(encoded, s.machineID, s.generation)
	if err != nil {
		return portableState{}, err
	}
	key := portableDerivedKey(s.wrapping, s.machineID, s.generation)
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return portableState{}, errors.Join(ErrInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return portableState{}, errors.Join(ErrInvalid, err)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		clear(nonce)
		return portableState{}, ErrInvalid
	}
	defer clear(nonce)
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < aead.Overhead() || len(ciphertext) > portableMaxFileSize {
		clear(ciphertext)
		return portableState{}, ErrInvalid
	}
	defer clear(ciphertext)
	plaintext, err := aead.Open(nil, nonce, ciphertext, portableAAD(s.machineID, s.generation))
	if err != nil {
		clear(plaintext)
		return portableState{}, ErrInvalid
	}
	defer clear(plaintext)
	return decodePortableState(plaintext, s.machineID, s.generation)
}

func (s *portableStore) write(state portableState) error {
	if s == nil || isZeroKey(s.wrapping) || !validIdentity(s.machineID) || s.generation == 0 {
		return ErrInvalid
	}
	if err := validatePortableState(state, s.machineID, s.generation); err != nil {
		return err
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	defer clear(plaintext)
	key := portableDerivedKey(s.wrapping, s.machineID, s.generation)
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	nonce := make([]byte, aead.NonceSize())
	reader := s.random
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, nonce); err != nil {
		clear(nonce)
		return errors.Join(ErrUnavailable, err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, portableAAD(s.machineID, s.generation))
	envelope := portableEnvelope{
		Schema: portableEnvelopeSchema, MachineID: s.machineID,
		Generation: s.generation,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	clear(nonce)
	clear(ciphertext)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	defer clear(encoded)
	if len(encoded) > portableMaxFileSize {
		return ErrInvalid
	}
	if err := atomicfile.Write(s.path, encoded, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func decodePortableEnvelope(encoded []byte, machineID string, generation uint64) (portableEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > portableMaxFileSize {
		return portableEnvelope{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var envelope portableEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return portableEnvelope{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return portableEnvelope{}, ErrInvalid
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return portableEnvelope{}, ErrInvalid
	}
	if envelope.Schema != portableEnvelopeSchema || envelope.MachineID != machineID || envelope.Generation != generation {
		return portableEnvelope{}, ErrInvalid
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 || envelope.Nonce != base64.RawURLEncoding.EncodeToString(nonce) {
		clear(nonce)
		return portableEnvelope{}, ErrInvalid
	}
	clear(nonce)
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > portableMaxFileSize || envelope.Ciphertext != base64.RawURLEncoding.EncodeToString(ciphertext) {
		clear(ciphertext)
		return portableEnvelope{}, ErrInvalid
	}
	clear(ciphertext)
	return envelope, nil
}

func decodePortableState(encoded []byte, machineID string, generation uint64) (portableState, error) {
	if len(encoded) == 0 || len(encoded) > portableMaxFileSize {
		return portableState{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var state portableState
	if err := decoder.Decode(&state); err != nil {
		return portableState{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return portableState{}, ErrInvalid
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return portableState{}, ErrInvalid
	}
	if err := validatePortableState(state, machineID, generation); err != nil {
		return portableState{}, err
	}
	return state, nil
}

func validatePortableState(state portableState, machineID string, generation uint64) error {
	if state.Schema != portableStateSchema || state.MachineID != machineID || state.Generation != generation || state.Values == nil || len(state.Values) > 16 {
		return ErrInvalid
	}
	for reference, value := range state.Values {
		if err := validatePortableReference(reference); err != nil || len(value) == 0 || len(value) > portableMaxValueSize || strings.ContainsRune(value, '\x00') {
			return ErrInvalid
		}
	}
	return nil
}

func validatePortableReference(reference string) error {
	if reference == "" || len(reference) > portableMaxReference || strings.ContainsAny(reference, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

func portableDerivedKey(wrapping [32]byte, machineID string, generation uint64) [32]byte {
	mac := hmac.New(sha256.New, wrapping[:])
	_, _ = mac.Write([]byte(portableWrapDomain))
	_, _ = mac.Write([]byte(machineID))
	var generationBytes [8]byte
	binary.BigEndian.PutUint64(generationBytes[:], generation)
	_, _ = mac.Write(generationBytes[:])
	derived := mac.Sum(nil)
	defer clear(derived)
	var result [32]byte
	copy(result[:], derived)
	return result
}

func portableAAD(machineID string, generation uint64) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%d", portableEnvelopeSchema, machineID, generation))
}

func preparePortableDirectories(stateRoot string) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return ErrInvalid
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if err := ensurePortableDirectory(stateRoot); err != nil {
		return err
	}
	directory := filepath.Join(stateRoot, "environment")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return ensurePortableDirectory(directory)
}

func ensurePortableDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !portableOwnerIsCurrent(info) {
		return ErrInvalid
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

func securePortableFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && stat.Nlink == 1 && info.Mode().Perm()&0o077 == 0 && portableOwnerIsCurrent(info)
}

func portableOwnerIsCurrent(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}

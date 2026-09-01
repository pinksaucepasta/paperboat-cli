//go:build linux

package environmentkey

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

type ProvisionConfig struct {
	CiphertextPath string
	MachineID      string
	Generation     uint64
	Random         io.Reader
	Runner         CredentialRunner
	Writer         CredentialWriter
}

type CredentialWriter interface {
	Write(string, []byte) error
}

type rootCredentialWriter struct{}

func (rootCredentialWriter) Write(path string, value []byte) error {
	return atomicfile.Write(path, value, atomicfile.Options{Mode: 0o600, OwnerUID: 0, OwnerGID: 0})
}

type CredentialRunner interface {
	Run(context.Context, []string, []byte, int64) ([]byte, error)
}

type ExecCredentialRunner struct{}

func (ExecCredentialRunner) Run(ctx context.Context, arguments []string, stdin []byte, maximum int64) ([]byte, error) {
	if ctx == nil || len(arguments) == 0 || maximum < 1 {
		return nil, ErrInvalid
	}
	command := exec.CommandContext(ctx, "systemd-creds", arguments...)
	command.Stdin = bytes.NewReader(stdin)
	var output bytes.Buffer
	command.Stdout = &boundedWriter{writer: &output, remaining: maximum}
	var stderr bytes.Buffer
	command.Stderr = &boundedWriter{writer: &stderr, remaining: 4096}
	if err := command.Run(); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return output.Bytes(), nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > w.remaining {
		return 0, errors.New("credential command output exceeds limit")
	}
	w.remaining -= int64(len(value))
	return w.writer.Write(value)
}

// EnsureSystemdCredential creates or validates the host-only encrypted
// credential. No plaintext key is written to a file or passed in argv.
func EnsureSystemdCredential(ctx context.Context, config ProvisionConfig) (bool, error) {
	if ctx == nil || !validProvisionConfig(config) {
		return false, ErrInvalid
	}
	if material, err := loadProvisioned(ctx, config); err == nil {
		material.Destroy()
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errGenerationChanged) {
		return false, err
	}
	runner := config.Runner
	if runner == nil {
		runner = ExecCredentialRunner{}
	}
	if _, err := runner.Run(ctx, []string{"setup"}, nil, 4096); err != nil {
		return false, err
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	private := make([]byte, privateKeySize)
	if _, err := io.ReadFull(random, private); err != nil {
		return false, err
	}
	defer clear(private)
	if _, err := ecdh.X25519().NewPrivateKey(private); err != nil {
		return false, ErrInvalid
	}
	record, err := json.Marshal(credentialMetadata{
		Schema: linuxCredentialMetadataSchema, MachineID: config.MachineID,
		Generation: config.Generation, PrivateKey: base64.RawURLEncoding.EncodeToString(private),
	})
	if err != nil {
		return false, err
	}
	defer clear(record)
	ciphertext, err := runner.Run(ctx, []string{"encrypt", "--name=" + CredentialName, "--with-key=host", "-", "-"}, record, 64<<10)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 64<<10 || bytes.Contains(ciphertext, private) {
		clear(ciphertext)
		return false, errors.Join(ErrUnavailable, err)
	}
	decrypted, err := runner.Run(ctx, []string{"decrypt", "--name=" + CredentialName, "-", "-"}, ciphertext, 4096)
	if err != nil || !bytes.Equal(decrypted, record) {
		clear(ciphertext)
		clear(decrypted)
		return false, errors.Join(ErrUnavailable, err)
	}
	clear(decrypted)
	if err := secureCredentialDirectory(filepath.Dir(config.CiphertextPath)); err != nil {
		clear(ciphertext)
		return false, err
	}
	writer := config.Writer
	if writer == nil {
		writer = rootCredentialWriter{}
	}
	if err := writer.Write(config.CiphertextPath, ciphertext); err != nil {
		clear(ciphertext)
		return false, err
	}
	clear(ciphertext)
	return true, nil
}

var errGenerationChanged = errors.New("environment host key generation changed")

func loadProvisioned(ctx context.Context, config ProvisionConfig) (Material, error) {
	ciphertext, err := readRootFile(config.CiphertextPath, 64<<10)
	if err != nil {
		return Material{}, err
	}
	runner := config.Runner
	if runner == nil {
		runner = ExecCredentialRunner{}
	}
	plaintext, err := runner.Run(ctx, []string{"decrypt", "--name=" + CredentialName, "-", "-"}, ciphertext, 4096)
	clear(ciphertext)
	if err != nil {
		clear(plaintext)
		return Material{}, errors.Join(ErrUnavailable, err)
	}
	metadata, private, err := parseCredentialRecord(plaintext)
	clear(plaintext)
	if err != nil {
		return Material{}, err
	}
	if metadata.MachineID != config.MachineID || metadata.Generation != config.Generation {
		clear(private)
		return Material{}, errGenerationChanged
	}
	result := Material{Generation: metadata.Generation}
	copy(result.Private[:], private)
	clear(private)
	if _, err := result.Public(); err != nil {
		result.Destroy()
		return Material{}, ErrInvalid
	}
	return result, nil
}

func validProvisionConfig(config ProvisionConfig) bool {
	return filepath.IsAbs(config.CiphertextPath) && filepath.Clean(config.CiphertextPath) == config.CiphertextPath &&
		!strings.ContainsAny(config.CiphertextPath, "\x00\r\n") && validIdentity(config.MachineID) && config.Generation > 0
}

func readRootFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInvalid
	}
	if status, ok := info.Sys().(*syscall.Stat_t); !ok || status.Uid != 0 {
		return nil, ErrInvalid
	}
	return os.ReadFile(path)
}

func secureCredentialDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalid
	}
	if status, ok := info.Sys().(*syscall.Stat_t); !ok || status.Uid != 0 {
		return ErrInvalid
	}
	return os.Chmod(path, 0o700)
}

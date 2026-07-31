//go:build darwin || linux

package hostservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type fakeUpdateFetcher struct{ body []byte }

func (f fakeUpdateFetcher) Fetch(_ context.Context, _ bootstrap.ArtifactManifest, _ string, directory string) (string, error) {
	file, err := os.CreateTemp(directory, ".paperboat-artifact-")
	if err != nil {
		return "", err
	}
	if err := file.Chmod(0o700); err != nil {
		file.Close()
		return "", err
	}
	_, err = file.Write(f.body)
	return file.Name(), errors.Join(err, file.Close())
}

type fakeUpdateServices struct{ workerRestarts, hostRestarts int }

func (s *fakeUpdateServices) RestartWorker(context.Context) error { s.workerRestarts++; return nil }
func (s *fakeUpdateServices) RestartHost()                        { s.hostRestarts++ }

type fakeUpdateHealth struct{ err error }

func (h fakeUpdateHealth) Check(context.Context, string) error { return h.err }

func TestRootUpdateActivatesPBArtifactAndPreservesPrevious(t *testing.T) {
	manager, artifact := testUpdateManager(t, nil)
	version, err := manager.activate(context.Background(), artifact)
	if err != nil || version != "2026.07.27" {
		t.Fatalf("activate version=%q err=%v", version, err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("new")))
	if info, err := os.Stat(manager.config.BinaryPath); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode=%v err=%v", info.Mode().Perm(), err)
	}
	assertFileBody(t, manager.config.BinaryPath+".previous", string(testBinary("old")))
	services := manager.services.(*fakeUpdateServices)
	if services.workerRestarts != 1 || services.hostRestarts != 1 {
		t.Fatalf("restarts=%+v", services)
	}
	entry, err := manager.loadJournal()
	if err != nil || entry.Stage != "committed" || entry.Version != version {
		t.Fatalf("journal=%+v err=%v", entry, err)
	}
	if replayed, err := manager.activate(context.Background(), artifact); err != nil || replayed != version || services.workerRestarts != 1 || services.hostRestarts != 1 {
		t.Fatalf("replay version=%q err=%v restarts=%+v", replayed, err, services)
	}
}

func TestRootUpdateHealthFailureRollsBackPB(t *testing.T) {
	manager, artifact := testUpdateManager(t, errors.New("new runtime unhealthy"))
	if _, err := manager.activate(context.Background(), artifact); err == nil {
		t.Fatal("health failure was accepted")
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
	if _, err := os.Stat(manager.journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal error=%v", err)
	}
	if count := manager.RollbackCount(); count != 1 {
		t.Fatalf("rollback count=%d", count)
	}
}

func TestRootUpdateRejectsSignedBinaryForDifferentTarget(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	foreign := make([]byte, 32)
	if runtime.GOOS == "linux" {
		binary.LittleEndian.PutUint32(foreign[:4], 0xfeedfacf)
		binary.LittleEndian.PutUint32(foreign[4:8], 0x0100000c)
	} else {
		copy(foreign, "\x7fELF")
		foreign[4], foreign[5] = 2, 1
		binary.LittleEndian.PutUint16(foreign[18:20], 62)
	}
	artifact, publicKey := signedUpdate(t, foreign)
	manager.config.PublicKey, manager.fetcher = publicKey, fakeUpdateFetcher{body: foreign}
	if _, err := manager.activate(context.Background(), artifact); !errors.Is(err, ErrUpdateInvalid) {
		t.Fatalf("foreign binary error=%v", err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
}

func TestRootUpdateRecoveryRollsBackInterruptedActivation(t *testing.T) {
	manager, _ := testUpdateManager(t, nil)
	if err := os.Rename(manager.config.BinaryPath, manager.config.BinaryPath+".rollback"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.config.BinaryPath, testBinary("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	entry := updateJournal{Schema: updateJournalSchemaV1, Stage: "checking", Version: "2026.07.27", PreviousVersion: "2026.07.26", UpdatedAt: time.Now().UTC()}
	if err := manager.writeJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := manager.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, manager.config.BinaryPath, string(testBinary("old")))
	if count := manager.RollbackCount(); count != 1 {
		t.Fatalf("recovery rollback count=%d", count)
	}
}

func TestReleaseVersionComparisonIncludesRevision(t *testing.T) {
	for _, version := range []string{"2026.07.25", "2026.07.25.4"} {
		if !validReleaseVersion(version) {
			t.Fatalf("valid version rejected: %s", version)
		}
	}
	for _, version := range []string{"2026.07", "2026.07.25.4.1", "2026.07.x"} {
		if validReleaseVersion(version) {
			t.Fatalf("invalid version accepted: %s", version)
		}
	}
}

func testUpdateManager(t *testing.T, healthErr error) (*UpdateManager, bootstrap.ArtifactManifest) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	install, state := filepath.Join(root, "install"), filepath.Join(root, "state")
	for _, directory := range []string{install, state} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binaryPath := filepath.Join(install, "pb")
	if err := os.WriteFile(binaryPath, testBinary("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	newBody := testBinary("new")
	artifact, publicKey := signedUpdate(t, newBody)
	manager := &UpdateManager{
		config:   UpdateConfig{StateRoot: state, BinaryPath: binaryPath, PublicKey: publicKey, CurrentVersion: "2026.07.26", ListenAddress: "127.0.0.1:8080"},
		ownerUID: os.Getuid(), fetcher: fakeUpdateFetcher{body: newBody}, services: &fakeUpdateServices{}, health: fakeUpdateHealth{err: healthErr},
		journal: filepath.Join(state, "update-journal.json"), current: filepath.Join(state, "update-current.json"), rollbacks: filepath.Join(state, "update-rollbacks.json"),
	}
	if err := manager.validate(); err != nil {
		t.Fatal(err)
	}
	return manager, artifact
}

func testBinary(label string) []byte {
	header := make([]byte, 32)
	if runtime.GOOS == "linux" {
		copy(header, "\x7fELF")
		header[4], header[5] = 2, 1
		machine := uint16(62)
		if runtime.GOARCH == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(header[18:20], machine)
	} else {
		binary.LittleEndian.PutUint32(header[:4], 0xfeedfacf)
		cpu := uint32(0x01000007)
		if runtime.GOARCH == "arm64" {
			cpu = 0x0100000c
		}
		binary.LittleEndian.PutUint32(header[4:8], cpu)
	}
	return append(header, label...)
}

func signedUpdate(t *testing.T, body []byte) (bootstrap.ArtifactManifest, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	manifest := bootstrap.ArtifactManifest{Schema: bootstrap.ArtifactSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: "2026.07.27", Platform: runtime.GOOS, Architecture: runtime.GOARCH, URL: "https://updates.example.test/pb", ByteLength: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
	payload, _ := json.Marshal(struct {
		Architecture string `json:"architecture"`
		ByteLength   int64  `json:"byte_length"`
		Kind         string `json:"kind"`
		Platform     string `json:"platform"`
		Schema       string `json:"schema"`
		SHA256       string `json:"sha256"`
		URL          string `json:"url"`
		Version      string `json:"version"`
	}{manifest.Architecture, manifest.ByteLength, manifest.Kind, manifest.Platform, manifest.Schema, manifest.SHA256, manifest.URL, manifest.Version})
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return manifest, base64.RawURLEncoding.EncodeToString(publicKey)
}

func assertFileBody(t *testing.T, path, expected string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || string(body) != expected {
		t.Fatalf("%s body=%q err=%v", path, body, err)
	}
}

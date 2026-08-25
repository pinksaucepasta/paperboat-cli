package bootstrap

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type testTUFRepository struct {
	root  []byte
	files map[string][]byte
}

func newTestTUFRepository(t *testing.T, body []byte, version string, expires time.Time) testTUFRepository {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(time.Now().UTC().Add(24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	targetPath := "pb-" + runtime.GOOS + "-" + runtime.GOARCH
	targets := metadata.Targets(time.Now().UTC().Add(24 * time.Hour))
	info, err := metadata.TargetFile().FromBytes(targetPath, body, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	custom, _ := json.Marshal(tufTargetCustom{ArtifactTargetSchemaV1, ArtifactKindPB, version, runtime.GOOS, runtime.GOARCH})
	raw := json.RawMessage(custom)
	info.Custom, info.Path = &raw, targetPath
	targets.Signed.Targets[targetPath] = info
	snapshot := metadata.Snapshot(time.Now().UTC().Add(24 * time.Hour))
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(1)
	timestamp := metadata.Timestamp(expires)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	for _, item := range []struct {
		role  string
		value interface {
			Sign(signature.Signer) (*metadata.Signature, error)
		}
	}{
		{"root", root}, {"targets", targets}, {"snapshot", snapshot}, {"timestamp", timestamp},
	} {
		signer, err := signature.LoadSigner(keys[item.role], crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.value.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	rootBytes, _ := root.ToBytes(false)
	targetsBytes, _ := targets.ToBytes(false)
	snapshotBytes, _ := snapshot.ToBytes(false)
	timestampBytes, _ := timestamp.ToBytes(false)
	digest := hex.EncodeToString(info.Hashes["sha256"])
	return testTUFRepository{root: rootBytes, files: map[string][]byte{
		"/metadata/timestamp.json":              timestampBytes,
		"/metadata/1.snapshot.json":             snapshotBytes,
		"/metadata/1.targets.json":              targetsBytes,
		"/targets/" + digest + "." + targetPath: body,
	}}
}

func (r testTUFRepository) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := r.files[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write(body)
	}))
}

func descriptor(repositoryURL, version string) ArtifactTarget {
	return ArtifactTarget{Schema: ArtifactTargetSchemaV1, Kind: ArtifactKindPB, Version: version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: repositoryURL, TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH}
}

func TestFetchVerifiedArtifactThroughTUF(t *testing.T) {
	body := []byte("verified pb binary")
	repository := newTestTUFRepository(t, body, "2026.08.07", time.Now().UTC().Add(time.Hour))
	server := repository.server(t)
	defer server.Close()
	path, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("artifact=%q err=%v", got, err)
	}
	if err := secureArtifactFile(path); err != nil {
		t.Fatalf("artifact security error=%v", err)
	}
}

func TestFetchVerifiedArtifactRejectsTargetMismatch(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("expected"), "2026.08.07", time.Now().UTC().Add(time.Hour))
	for path := range repository.files {
		if len(path) > len("/targets/") && path[:len("/targets/")] == "/targets/" {
			repository.files[path] = []byte("tampered")
		}
	}
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("tampered target was accepted")
	}
}

func TestFetchVerifiedArtifactRejectsExpiredTimestampAndWrongVersion(t *testing.T) {
	repository := newTestTUFRepository(t, []byte("pb"), "2026.08.07", time.Now().UTC().Add(-time.Minute))
	server := repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.07"), filepath.Join(t.TempDir(), "expired-tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("expired timestamp was accepted")
	}
	repository = newTestTUFRepository(t, []byte("pb"), "2026.08.07", time.Now().UTC().Add(time.Hour))
	server = repository.server(t)
	defer server.Close()
	if _, err := fetchVerifiedArtifact(context.Background(), descriptor(server.URL, "2026.08.08"), filepath.Join(t.TempDir(), "wrong-version-tuf"), server.Client(), repository.root, runtime.GOOS, runtime.GOARCH); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("wrong version error=%v", err)
	}
}

func TestVerifyArtifactTargetRejectsWrongPlatformAndOrigin(t *testing.T) {
	target := descriptor("https://updates.example.test/paperboat", "2026.08.07")
	target.Platform = "unsupported"
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("platform err=%v", err)
	}
	target = descriptor("http://updates.example.test/paperboat", "2026.08.07")
	if err := VerifyArtifactTarget(target); !errors.Is(err, ErrArtifactTarget) {
		t.Fatalf("origin err=%v", err)
	}
}

func TestReleaseIndexDiscoveryRejectsUnsignedTargetSelectionInputs(t *testing.T) {
	state := filepath.Join(t.TempDir(), "tuf")
	for _, repository := range []string{
		"http://releases.example.test", "https://user@releases.example.test",
		"https://releases.example.test?target=attacker", "https://releases.example.test/#fragment",
	} {
		if _, err := FetchVerifiedReleaseIndex(context.Background(), repository, state, nil, time.Now().UTC()); !errors.Is(err, ErrArtifactTarget) {
			t.Fatalf("repository=%q error=%v", repository, err)
		}
	}
}

func TestFetchVerifiedReleaseComponentRejectsMissingTargetMetadata(t *testing.T) {
	repository := newTestReleaseComponentRepositoryWithoutTargets(t)
	server := repository.server(t)
	defer server.Close()

	now := time.Now().UTC()
	index := testLinuxReleaseIndex()
	if _, err := fetchVerifiedReleaseComponentWithRoot(context.Background(), server.URL, filepath.Join(t.TempDir(), "tuf"), index, "cli", server.Client(), now, repository.root, "linux", "amd64"); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("missing signed target metadata error=%v", err)
	}
}

func TestReleaseComponentCustomValidatesPlatformSchemas(t *testing.T) {
	for _, fixture := range []struct {
		platform, architecture, format string
	}{
		{"linux", "arm64", "elf"},
		{"darwin", "arm64", "mach-o"},
	} {
		t.Run(fixture.platform, func(t *testing.T) {
			index := releaseindex.Index{Version: "2026.08.22.22"}
			target := releaseindex.Target{Component: "cli", Platform: fixture.platform, Architecture: fixture.architecture, BinaryFormat: fixture.format}
			custom := testReleaseComponentCustom(index, target, nil)
			raw := marshalJSON(t, custom)
			decoded, ok := decodeReleaseComponentCustom(raw)
			if !ok || !validReleaseComponentCustom(decoded, index, target, "cli") {
				t.Fatal("matching published component schema was rejected")
			}

			custom.BinaryFormat = "unknown"
			decoded, ok = decodeReleaseComponentCustom(marshalJSON(t, custom))
			if !ok || validReleaseComponentCustom(decoded, index, target, "cli") {
				t.Fatal("unknown binary_format was accepted")
			}
			custom = testReleaseComponentCustom(index, target, &tufWindowsNativeQualificationBinding{})
			decoded, ok = decodeReleaseComponentCustom(marshalJSON(t, custom))
			if !ok || validReleaseComponentCustom(decoded, index, target, "cli") {
				t.Fatal("native qualification was accepted on a non-Windows component")
			}
			unknownField := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unexpected_binary_format":"elf"}`)...)
			if _, ok := decodeReleaseComponentCustom(unknownField); ok {
				t.Fatal("unknown component custom field was accepted")
			}
		})
	}
}

func TestWindowsReleaseComponentQualificationBindsEvidence(t *testing.T) {
	index := testWindowsReleaseIndex()
	target, _ := index.Component("cli")
	binding := testWindowsQualificationBinding(index, target)
	custom := testReleaseComponentCustom(index, target, binding)
	decoded, ok := decodeReleaseComponentCustom(marshalJSON(t, custom))
	if !ok || !validReleaseComponentCustom(decoded, index, target, "cli") || !validWindowsNativeQualificationBinding(decoded.NativeQualification, index, target) {
		t.Fatal("matching published Windows component schema was rejected")
	}
	custom.NativeQualification = nil
	if validReleaseComponentCustom(custom, index, target, "cli") {
		t.Fatal("Windows component without native qualification was accepted")
	}
	custom = testReleaseComponentCustom(index, target, binding)
	custom.BinaryFormat = "elf"
	if validReleaseComponentCustom(custom, index, target, "cli") {
		t.Fatal("Windows component with a mismatched binary_format was accepted")
	}
	if !validWindowsNativeQualificationTargetCustom(marshalJSON(t, tufWindowsNativeQualificationTargetCustom{
		Schema: "paperboat.windows-native-qualification/v1", Kind: "windows-native-qualification", Platform: "windows", Architecture: "amd64", Status: "passed",
	}), target.Architecture) {
		t.Fatal("matching Windows qualification target custom metadata was rejected")
	}
	evidence := testWindowsQualificationEvidence(index, binding)
	evidenceRaw := marshalJSON(t, evidence)
	if !validWindowsNativeQualificationEvidence(evidenceRaw, binding, index) {
		t.Fatal("matching Windows qualification evidence was rejected")
	}
	withoutResult := evidence
	withoutResult.QualificationResult = tufWindowsNativeQualificationResultBinding{}
	if validWindowsNativeQualificationEvidence(marshalJSON(t, withoutResult), binding, index) {
		t.Fatal("Windows qualification evidence without its result binding was accepted")
	}

	binding.ArtifactSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if validWindowsNativeQualificationBinding(binding, index, target) {
		t.Fatal("qualification binding with a mismatched component digest was accepted")
	}
	binding = testWindowsQualificationBinding(index, target)
	unknownField := append(append([]byte{}, evidenceRaw[:len(evidenceRaw)-1]...), []byte(`,"unexpected_evidence_field":true}`)...)
	if validWindowsNativeQualificationEvidence(unknownField, binding, index) {
		t.Fatal("qualification evidence with an unknown field was accepted")
	}
}

func testReleaseComponentCustom(index releaseindex.Index, target releaseindex.Target, qualification *tufWindowsNativeQualificationBinding) tufReleaseComponentCustom {
	return tufReleaseComponentCustom{
		Schema: "paperboat.tuf-component/v1", Kind: "component", Component: target.Component, Version: index.Version,
		Platform: target.Platform, Architecture: target.Architecture, BinaryFormat: target.BinaryFormat, NativeQualification: qualification,
	}
}

func testWindowsReleaseIndex() releaseindex.Index {
	components := []string{"cli", "runtime", "hostd", "updater", "launcher"}
	targets := make([]releaseindex.Target, 0, len(components))
	for number, component := range components {
		targets = append(targets, releaseindex.Target{
			Component: component, TargetPath: component + "-windows-amd64", SHA256: fmt.Sprintf("%064x", number+1), Length: int64(number + 1),
			Platform: "windows", Architecture: "amd64", BinaryFormat: "pe",
		})
	}
	return releaseindex.Index{
		Version: "2026.08.22.22", Platform: "windows", Architecture: "amd64", BinaryFormat: "pe", Targets: targets,
		Stability: "stable", NativeTested: true, TestedWindowsBuilds: []string{"26100"},
	}
}

func testWindowsQualificationBinding(index releaseindex.Index, target releaseindex.Target) *tufWindowsNativeQualificationBinding {
	return &tufWindowsNativeQualificationBinding{
		Schema: "paperboat.windows-native-qualification/v1", EvidenceTarget: "windows-amd64-native-qualification.json",
		EvidenceSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseVersion: index.Version,
		Platform: "windows", Architecture: "amd64", Status: "passed", NativeTested: true, WindowsBuild: "26100", Runner: "windows-2025",
		ArtifactSHA256: target.SHA256, ArtifactLength: target.Length,
	}
}

func testWindowsQualificationEvidence(index releaseindex.Index, binding *tufWindowsNativeQualificationBinding) tufWindowsNativeQualification {
	artifacts := make([]tufWindowsNativeQualifiedArtifact, 0, len(index.Targets))
	for _, target := range index.Targets {
		artifacts = append(artifacts, tufWindowsNativeQualifiedArtifact{
			Component: target.Component, TargetPath: target.TargetPath, SHA256: target.SHA256, Length: target.Length,
			Platform: "windows", Architecture: "amd64", Status: "passed",
		})
	}
	return tufWindowsNativeQualification{
		Schema: "paperboat.windows-native-qualification/v1", ReleaseVersion: index.Version, Platform: "windows", Architecture: "amd64",
		Status: "passed", NativeTested: true, WindowsBuild: binding.WindowsBuild, Runner: binding.Runner,
		QualificationResult: tufWindowsNativeQualificationResultBinding{
			Schema: "paperboat.windows-native-qualification-result-binding/v1", TargetPath: "windows-amd64-native-qualification-report.json",
			SHA256: strings.Repeat("b", 64), Length: 100, NativeTestSHA256: strings.Repeat("c", 64), NativeTestLength: 200,
		},
		Artifacts: artifacts,
	}
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTestReleaseComponentRepositoryWithoutTargets(t *testing.T) testTUFRepository {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(time.Now().UTC().Add(24 * time.Hour))
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
	}
	targets := metadata.Targets(time.Now().UTC().Add(24 * time.Hour))
	snapshot := metadata.Snapshot(time.Now().UTC().Add(24 * time.Hour))
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(1)
	timestamp := metadata.Timestamp(time.Now().UTC().Add(time.Hour))
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	for _, item := range []struct {
		role  string
		value interface {
			Sign(signature.Signer) (*metadata.Signature, error)
		}
	}{
		{"root", root}, {"targets", targets}, {"snapshot", snapshot}, {"timestamp", timestamp},
	} {
		signer, err := signature.LoadSigner(keys[item.role], crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.value.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	targetsBytes, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestampBytes, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return testTUFRepository{root: rootBytes, files: map[string][]byte{
		"/metadata/timestamp.json":  timestampBytes,
		"/metadata/1.snapshot.json": snapshotBytes,
		"/metadata/1.targets.json":  targetsBytes,
	}}
}

func testLinuxReleaseIndex() releaseindex.Index {
	components := []string{"cli", "runtime", "hostd", "updater", "launcher"}
	targets := make([]releaseindex.Target, 0, len(components))
	for number, component := range components {
		targets = append(targets, releaseindex.Target{
			Component: component, TargetPath: component + "-linux-amd64", SHA256: fmt.Sprintf("%064x", number+1), Length: int64(number + 1),
			Platform: "linux", Architecture: "amd64", BinaryFormat: "elf",
		})
	}
	return releaseindex.Index{
		Schema: releaseindex.SchemaV1, ReleaseID: "rel_2026.08.22.22", Version: "2026.08.22.22", Channel: "stable", Severity: "routine",
		CreatedAt: time.Now().UTC(), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf", Targets: targets,
		HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: 1,
		Rollout: releaseindex.Rollout{Schema: releaseindex.RolloutSchemaV1, CohortSeed: "release-2026.08.22.22", Percentage: 100},
	}
}

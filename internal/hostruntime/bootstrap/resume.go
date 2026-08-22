package bootstrap

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
)

const resumeSchema = "paperboat.byod-resume/v1"

var (
	ErrResumeNotFound      = errors.New("BYOD bootstrap resume state was not found")
	ErrResumeBinding       = errors.New("BYOD bootstrap resume state does not match this machine or enrollment")
	ErrResumeExpired       = errors.New("BYOD bootstrap resume state has expired")
	ErrResumeTokenRequired = errors.New("BYOD bootstrap resume state requires the original enrollment token")
)

// ResumeRecord is the protected, local journal for a one-shot machine
// enrollment. It never stores the enrollment token itself, only its digest.
// Material is retained until the host installation commits so ordinary retries
// remain local; the verifier-bound server recovery path is reserved for a lost
// or expired material response.
type ResumeRecord struct {
	Schema                  string    `json:"schema"`
	ServerURL               string    `json:"server_url"`
	PublicIdentityKey       string    `json:"public_identity_key"`
	EnrollmentTokenSHA      string    `json:"enrollment_token_sha256"`
	EnrollmentTokenRequired bool      `json:"enrollment_token_required,omitempty"`
	DisplayName             string    `json:"display_name"`
	SetupMode               string    `json:"setup_mode"`
	Verifier                string    `json:"verifier"`
	PairingExpiresAt        time.Time `json:"pairing_expires_at"`
	PairingStarted          bool      `json:"pairing_started,omitempty"`
	Material                *Material `json:"material,omitempty"`
	ClientInstalled         bool      `json:"client_installed,omitempty"`
	RuntimeEnrolled         bool      `json:"runtime_enrolled,omitempty"`
}

func ResumePath(stateRoot string) string {
	return filepath.Join(stateRoot, "bootstrap-resume.json")
}

// NewResumeRecord creates the pre-pairing journal. Keeping the verifier lets
// a process that dies after server pairing but before material delivery resume
// polling without attempting a second pairing.
func NewResumeRecord(serverURL, publicIdentityKey, enrollmentToken, displayName, setupMode, verifier string, expiresAt time.Time) ResumeRecord {
	return ResumeRecord{
		Schema:                  resumeSchema,
		ServerURL:               strings.TrimRight(strings.TrimSpace(serverURL), "/"),
		PublicIdentityKey:       strings.TrimSpace(publicIdentityKey),
		EnrollmentTokenSHA:      enrollmentTokenDigest(enrollmentToken),
		EnrollmentTokenRequired: strings.TrimSpace(enrollmentToken) != "",
		DisplayName:             strings.TrimSpace(displayName),
		SetupMode:               strings.TrimSpace(setupMode),
		Verifier:                strings.TrimSpace(verifier),
		PairingExpiresAt:        expiresAt,
	}
}

func SaveResume(stateRoot string, record ResumeRecord) error {
	if err := validateResumeRecord(record, false); err != nil {
		return err
	}
	if err := ensureResumeDirectory(stateRoot); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicfile.Write(ResumePath(stateRoot), encoded, atomicfile.CurrentOwnerOptions(0o600))
}

// LoadResume validates the file and its immutable binding. An empty token is
// accepted only after the server-pairing phase is durably recorded, which is
// necessary when a token-file installer consumed the local file before a
// later process failed. Before pairing, a token-backed journal must still be
// given its original token so it cannot silently become an identity pairing.
func LoadResume(stateRoot, serverURL, publicIdentityKey, enrollmentToken, displayName, setupMode string, now time.Time) (ResumeRecord, error) {
	if !filepath.IsAbs(stateRoot) || now.IsZero() {
		return ResumeRecord{}, ErrResumeBinding
	}
	path := ResumePath(stateRoot)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ResumeRecord{}, ErrResumeNotFound
	}
	if err != nil || !secureResumeFile(path, info, 512<<10) {
		return ResumeRecord{}, ErrResumeBinding
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return ResumeRecord{}, err
	}
	var record ResumeRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return ResumeRecord{}, ErrResumeBinding
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ResumeRecord{}, ErrResumeBinding
	}
	if err := validateResumeRecord(record, true); err != nil {
		return ResumeRecord{}, err
	}
	if strings.TrimRight(strings.TrimSpace(serverURL), "/") != record.ServerURL ||
		strings.TrimSpace(publicIdentityKey) != record.PublicIdentityKey ||
		strings.TrimSpace(displayName) != record.DisplayName ||
		strings.TrimSpace(setupMode) != record.SetupMode {
		return ResumeRecord{}, ErrResumeBinding
	}
	if record.requiresEnrollmentToken() && strings.TrimSpace(enrollmentToken) == "" && !record.PairingStarted {
		return ResumeRecord{}, ErrResumeTokenRequired
	}
	if strings.TrimSpace(enrollmentToken) != "" && enrollmentTokenDigest(enrollmentToken) != record.EnrollmentTokenSHA {
		return ResumeRecord{}, ErrResumeBinding
	}
	if record.Material != nil && !now.UTC().Before(record.Material.ExpiresAt) {
		return record, ErrResumeExpired
	}
	if record.Material == nil && !record.PairingExpiresAt.IsZero() && !now.UTC().Before(record.PairingExpiresAt) {
		return record, ErrResumeExpired
	}
	return record, nil
}

func ClearResume(stateRoot string) error {
	path := ResumePath(stateRoot)
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !secureResumeFile(path, info, 512<<10) {
		return ErrResumeBinding
	}
	return os.Remove(path)
}

func ValidateMaterial(material Material) error { return validateMaterial(material) }

// ValidateRecoveredMaterial binds renewed/replayed credentials to the exact
// machine installation already stored in the protected journal. Credentials
// and release artifacts may rotate, but machine ownership and installation
// generation must not change under the same verifier.
func ValidateRecoveredMaterial(previous, recovered Material, runtimeEnrolled bool) error {
	if previous.UserMachineID != recovered.UserMachineID ||
		previous.UserMachineEnrollmentID != recovered.UserMachineEnrollmentID ||
		previous.EnvironmentID != recovered.EnvironmentID ||
		runtimeEnrolled && previous.HelperID != recovered.HelperID ||
		previous.InstallationGeneration != recovered.InstallationGeneration ||
		previous.SetupMode != recovered.SetupMode ||
		normalizeBootstrapURL(previous.ControlURL) != normalizeBootstrapURL(recovered.ControlURL) {
		return fmt.Errorf("%w: recovered material changed the bound machine installation", ErrResumeBinding)
	}
	return nil
}

func enrollmentTokenDigest(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(digest[:])
}

func (record ResumeRecord) requiresEnrollmentToken() bool {
	// The digest check keeps journals written before the explicit boolean field
	// backwards compatible while still distinguishing an identity pairing from
	// a token-backed pairing before the server has accepted CreatePairing.
	return record.EnrollmentTokenRequired || record.EnrollmentTokenSHA != enrollmentTokenDigest("")
}

// RequiresEnrollmentTokenForRetry reports whether a retry would otherwise
// downgrade a token-backed pairing to an unauthenticated identity pairing.
// Once PairingStarted is true, an empty token is allowed because the server
// has already accepted the one-shot credential and the verifier is the resume
// binding. Callers must still refuse a new CreatePairing without the token.
func (record ResumeRecord) RequiresEnrollmentTokenForRetry(token string) bool {
	return record.requiresEnrollmentToken() && strings.TrimSpace(token) == ""
}

func validateResumeRecord(record ResumeRecord, loaded bool) error {
	if record.Schema != resumeSchema || !validResumeServer(record.ServerURL) || record.PublicIdentityKey == "" || len(record.EnrollmentTokenSHA) != sha256.Size*2 || record.DisplayName == "" || record.SetupMode != "host" && record.SetupMode != "client" || len(record.Verifier) < 32 || record.PairingExpiresAt.IsZero() {
		return ErrResumeBinding
	}
	if _, err := hex.DecodeString(record.EnrollmentTokenSHA); err != nil {
		return ErrResumeBinding
	}
	if loaded && record.Material == nil && record.ClientInstalled || record.RuntimeEnrolled && record.Material == nil {
		return ErrResumeBinding
	}
	if record.Material != nil {
		if !record.PairingStarted {
			return fmt.Errorf("%w: material exists before pairing started", ErrResumeBinding)
		}
		if err := validateMaterialFreshness(*record.Material, !loaded); err != nil {
			return fmt.Errorf("%w: material validation: %v", ErrResumeBinding, err)
		}
		if record.Material.SetupMode != record.SetupMode {
			return fmt.Errorf("%w: material setup mode %q does not match journal setup mode %q", ErrResumeBinding, record.Material.SetupMode, record.SetupMode)
		}
		if strings.TrimRight(strings.TrimSpace(record.Material.ControlURL), "/") != record.ServerURL {
			return fmt.Errorf("%w: material control URL %q does not match journal server URL %q", ErrResumeBinding, record.Material.ControlURL, record.ServerURL)
		}
	}
	return nil
}

func validResumeServer(value string) bool {
	return strings.HasPrefix(value, "https://") && !strings.ContainsAny(value, "\x00\r\n")
}

func ensureResumeDirectory(stateRoot string) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return ErrResumeBinding
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(stateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrResumeBinding
	}
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		return err
	}
	return nil
}

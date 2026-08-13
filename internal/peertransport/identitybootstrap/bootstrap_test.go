package identitybootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type bootstrapClientFunc func(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error)

func (bootstrapClientFunc) E2EERoot(context.Context) (api.E2EERoot, error) {
	return api.E2EERoot{}, &api.APIError{Status: 404, Code: "not_found"}
}

type existingRootClient struct{ root api.E2EERoot }

func (c existingRootClient) E2EERoot(context.Context) (api.E2EERoot, error) { return c.root, nil }
func (existingRootClient) BootstrapE2EE(context.Context, string, api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return api.E2EEBootstrapResult{}, errors.New("bootstrap must not run before pairing")
}

func (f bootstrapClientFunc) BootstrapE2EE(ctx context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
	return f(ctx, operation, input)
}

func TestBootstrapCreatesPersistsAndExactlyReplaysCLIIdentity(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	var firstOperation string
	var firstInput api.E2EEBootstrapInput
	client := bootstrapClientFunc(func(_ context.Context, operation string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		if firstOperation == "" {
			firstOperation, firstInput = operation, input
		} else if operation != firstOperation || input != firstInput {
			t.Fatalf("bootstrap replay changed: %q %+v", operation, input)
		}
		rootPublic, err := base64.RawURLEncoding.DecodeString(input.RootPublicKey)
		if err != nil || len(rootPublic) != ed25519.PublicKeySize {
			t.Fatal("invalid root public key")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(input.Certificate.Certificate)
		certificate, err := endpointidentity.Verify(raw, ed25519.PublicKey(rootPublic), endpointidentity.Expected{AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_1", Generation: 1}, now)
		if err != nil || certificate.Claims.Serial != 1 {
			t.Fatalf("certificate=%+v err=%v", certificate, err)
		}
		return api.E2EEBootstrapResult(input), nil
	})
	request := Request{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return now }}
	first, err := Bootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Bootstrap(context.Background(), request)
	if err != nil || first.RootFingerprint != second.RootFingerprint || first.CertificateFingerprint != second.CertificateFingerprint {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestBootstrapRejectsServerSubstitution(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	client := bootstrapClientFunc(func(_ context.Context, _ string, input api.E2EEBootstrapInput) (api.E2EEBootstrapResult, error) {
		input.Certificate.EndpointID = "other_cli"
		return api.E2EEBootstrapResult(input), nil
	})
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", Now: func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestBootstrapRequiresPairingWhenRemoteRootExistsWithoutLocalCustody(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	_, err := Bootstrap(context.Background(), Request{Store: store, Client: existingRootClient{root: api.E2EERoot{Version: 1, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 1}}, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1"})
	if !errors.Is(err, ErrPairingRequired) {
		t.Fatalf("err=%v", err)
	}
	entries, readErr := filepath.Glob(filepath.Join(root, "secrets", "*"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("secret entries=%v err=%v", entries, readErr)
	}
}

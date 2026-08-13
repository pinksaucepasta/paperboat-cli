package clientauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type certificateClientFunc func(context.Context, string, uint64) (api.EndpointCertificateDocument, error)

func (f certificateClientFunc) EndpointCertificate(ctx context.Context, endpoint string, generation uint64) (api.EndpointCertificateDocument, error) {
	return f(ctx, endpoint, generation)
}

func TestResolveBindsLocalCustodyAndRemoteCertificateToOneRoot(t *testing.T) {
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	issuer, accountID, cliID, machineID := "https://api.example.test", "account_01", "cli_01", "machine_01"
	keys, err := store.PeerIdentityKeys(issuer, accountID, cliID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	local, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: accountID, Role: endpointidentity.RoleCLI, EndpointID: cliID, NoisePublicKey: keys.NoisePublic, QUICPublicKey: keys.QUICPrivate.Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	localRaw, _ := local.MarshalBinary()
	if _, err := store.SavePeerCertificate(issuer, cliID, localRaw); err != nil {
		t.Fatal(err)
	}
	_, machineQUIC, _ := ed25519.GenerateKey(nil)
	var machineNoise [32]byte
	machineNoise[0] = 1
	machine, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: accountID, Role: endpointidentity.RoleMachine, EndpointID: machineID, NoisePublicKey: machineNoise, QUICPublicKey: machineQUIC.Public().(ed25519.PublicKey), Generation: 3, Serial: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	machineRaw, _ := machine.MarshalBinary()
	machineFingerprint := sha256.Sum256(machineRaw)
	rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	document := api.EndpointCertificateDocument{Version: 1, AccountID: accountID, RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: machineID, Role: "machine", Generation: 3, Serial: 2, IssuedAt: machine.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: machine.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(machineRaw), CertificateFingerprint: hex.EncodeToString(machineFingerprint[:])}
	authority, err := Resolve(context.Background(), Request{Store: store, Client: certificateClientFunc(func(_ context.Context, endpoint string, generation uint64) (api.EndpointCertificateDocument, error) {
		if endpoint != machineID || generation != 3 {
			t.Fatalf("endpoint=%s generation=%d", endpoint, generation)
		}
		return document, nil
	}), Issuer: issuer, AccountID: accountID, CLIClientSessionID: cliID, MachineID: machineID, MachineGeneration: 3, Now: now})
	if err != nil || authority.LocalCertificate.Claims.EndpointID != cliID || authority.MachineCertificate.Claims.EndpointID != machineID || len(authority.LocalKeys.QUICPrivate) != ed25519.PrivateKeySize {
		t.Fatalf("authority=%+v err=%v", authority, err)
	}
	authority.Clear()
	if len(authority.RootPublic) != 0 || len(authority.LocalKeys.RootPrivate) != 0 || len(authority.MachineCertificateRaw) != 0 {
		t.Fatal("authority was not cleared")
	}
	document.CertificateFingerprint = hex.EncodeToString(make([]byte, 32))
	if _, err := Resolve(context.Background(), Request{Store: store, Client: certificateClientFunc(func(context.Context, string, uint64) (api.EndpointCertificateDocument, error) { return document, nil }), Issuer: issuer, AccountID: accountID, CLIClientSessionID: cliID, MachineID: machineID, MachineGeneration: 3, Now: now}); err == nil {
		t.Fatal("metadata substitution was accepted")
	}
}

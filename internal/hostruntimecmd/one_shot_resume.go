package hostruntimecmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type oneShotResumeInput struct {
	StateRoot    string
	SetupMode    string
	TokenFile    string
	TokenFileErr error
	Config       bootstrap.Config
	Resume       bootstrap.ResumeRecord
	ResumeErr    error
	Status       io.Writer
	PollInterval time.Duration
}

type oneShotResumeOperations struct {
	Now              func() time.Time
	NewVerifier      func() (string, error)
	SaveResume       func(string, bootstrap.ResumeRecord) error
	ClearResume      func(string) error
	CreatePairing    func(context.Context, bootstrap.Config) (bootstrap.Pairing, error)
	WaitForMaterial  func(context.Context, bootstrap.Config, time.Time, time.Duration) (bootstrap.Material, error)
	RecoverMaterial  func(context.Context, bootstrap.Config, bool) (bootstrap.Material, error)
	ConsumeTokenFile func(string) error
}

func defaultOneShotResumeOperations() oneShotResumeOperations {
	return oneShotResumeOperations{
		Now: func() time.Time { return time.Now().UTC() },
		NewVerifier: func() (string, error) {
			value := make([]byte, 32)
			if _, err := rand.Read(value); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(value), nil
		},
		SaveResume:       bootstrap.SaveResume,
		ClearResume:      bootstrap.ClearResume,
		CreatePairing:    bootstrap.CreatePairing,
		WaitForMaterial:  bootstrap.WaitForMaterial,
		RecoverMaterial:  bootstrap.RecoverMaterial,
		ConsumeTokenFile: bootstrap.ConsumeEnrollmentTokenFile,
	}
}

// resumeOneShotEnrollment completes the verifier-bound portion of a one-shot
// enrollment. PairingStarted is persisted before CreatePairing because the
// server may commit even when the client loses the response. A retry therefore
// polls the same verifier first and never needs to replay a consumed token.
func resumeOneShotEnrollment(ctx context.Context, input oneShotResumeInput, operations oneShotResumeOperations) (bootstrap.Material, bootstrap.ResumeRecord, error) {
	if err := validateOneShotResumeOperations(operations); err != nil {
		return bootstrap.Material{}, bootstrap.ResumeRecord{}, err
	}
	if input.PollInterval <= 0 {
		input.PollInterval = 2 * time.Second
	}
	now := operations.Now().UTC()
	resume, resumeErr := input.Resume, input.ResumeErr
	resumeExpired := errors.Is(resumeErr, bootstrap.ErrResumeExpired)
	if resumeExpired {
		if !resume.PairingStarted {
			if err := operations.ClearResume(input.StateRoot); err != nil {
				return bootstrap.Material{}, resume, fmt.Errorf("clear expired unpaired machine enrollment state: %w", err)
			}
			resume, resumeErr, resumeExpired = bootstrap.ResumeRecord{}, bootstrap.ErrResumeNotFound, false
		} else {
			// The verifier is the only recovery binding after the one-shot token
			// has been consumed. Keep paired state and recover through the server.
			resumeErr = nil
		}
	}
	if errors.Is(resumeErr, bootstrap.ErrResumeTokenRequired) {
		return bootstrap.Material{}, resume, errors.New("the previous machine enrollment has not reached server pairing; provide the original enrollment token file to resume it")
	}
	if resumeErr != nil && !errors.Is(resumeErr, bootstrap.ErrResumeNotFound) {
		return bootstrap.Material{}, resume, resumeErr
	}
	if errors.Is(resumeErr, bootstrap.ErrResumeNotFound) && input.TokenFileErr != nil {
		return bootstrap.Material{}, resume, errors.New("enrollment token file must be an absolute regular owner-only file")
	}
	if resume.AuthenticatedSetup {
		return bootstrap.Material{}, resume, bootstrap.ErrResumeBinding
	}

	if errors.Is(resumeErr, bootstrap.ErrResumeNotFound) {
		verifier, err := operations.NewVerifier()
		if err != nil {
			return bootstrap.Material{}, resume, err
		}
		resume = bootstrap.NewResumeRecord(input.Config.ServerURL, input.Config.PublicIdentityKey, input.Config.EnrollmentToken, input.Config.DisplayName, input.SetupMode, verifier, now.Add(15*time.Minute))
		if err := operations.SaveResume(input.StateRoot, resume); err != nil {
			return bootstrap.Material{}, resume, fmt.Errorf("persist machine enrollment resume state: %w", err)
		}
	}

	if resume.Material != nil && !resumeExpired {
		if input.TokenFile != "" && input.TokenFileErr == nil {
			if err := operations.ConsumeTokenFile(input.TokenFile); err != nil {
				return bootstrap.Material{}, resume, fmt.Errorf("consume enrollment token file: %w", err)
			}
		}
		return *resume.Material, resume, nil
	}
	config := input.Config
	config.ServerURL = resume.ServerURL
	config.DisplayName = resume.DisplayName
	config.Verifier = resume.Verifier
	if resume.PairingStarted && input.Status != nil {
		fmt.Fprintln(input.Status, "Resuming one-shot machine enrollment...")
	}

	var material bootstrap.Material
	var err error
	if resumeExpired {
		material, err = operations.RecoverMaterial(ctx, config, resume.RuntimeEnrolled)
	} else {
		// Polling before CreatePairing closes the response-loss window after a
		// server commit. An unknown verifier returns InstallationUnavailable.
		material, err = operations.WaitForMaterial(ctx, config, resume.PairingExpiresAt, input.PollInterval)
	}
	if errors.Is(err, bootstrap.ErrInstallationUnavailable) {
		if resumeExpired && resume.PairingStarted {
			return bootstrap.Material{}, resume, bootstrap.ErrResumeExpired
		}
		if resume.RequiresEnrollmentTokenForRetry(config.EnrollmentToken) {
			return bootstrap.Material{}, resume, bootstrap.ErrResumeTokenRequired
		}
		// Persist the possible commit before the request. On an ambiguous
		// CreatePairing error, the next process must poll this verifier first.
		resume.PairingStarted = true
		if err := operations.SaveResume(input.StateRoot, resume); err != nil {
			return bootstrap.Material{}, resume, fmt.Errorf("persist machine pairing state: %w", err)
		}
		pairing, pairErr := operations.CreatePairing(ctx, config)
		if pairErr != nil {
			return bootstrap.Material{}, resume, pairErr
		}
		resume.PairingExpiresAt = pairing.ExpiresAt
		if err := operations.SaveResume(input.StateRoot, resume); err != nil {
			return bootstrap.Material{}, resume, fmt.Errorf("persist machine pairing state: %w", err)
		}
		if input.TokenFile != "" && input.TokenFileErr == nil {
			if err := operations.ConsumeTokenFile(input.TokenFile); err != nil {
				return bootstrap.Material{}, resume, fmt.Errorf("consume enrollment token file: %w", err)
			}
		}
		if input.Status != nil {
			fmt.Fprintln(input.Status, "Completing one-shot machine enrollment...")
		}
		material, err = operations.WaitForMaterial(ctx, config, pairing.ExpiresAt, input.PollInterval)
	}
	if err != nil {
		return bootstrap.Material{}, resume, err
	}
	if resume.Material != nil {
		if err := bootstrap.ValidateRecoveredMaterial(*resume.Material, material, resume.RuntimeEnrolled); err != nil {
			return bootstrap.Material{}, resume, err
		}
		if resume.ClientInstalled && !sameDurableClientSession(resume.Material.ClientSession, material.ClientSession) {
			return bootstrap.Material{}, resume, bootstrap.ErrResumeBinding
		}
	}
	resume.PairingStarted = true
	resume.Material = &material
	if err := operations.SaveResume(input.StateRoot, resume); err != nil {
		return bootstrap.Material{}, resume, fmt.Errorf("persist machine enrollment material: %w", err)
	}
	if input.TokenFile != "" && input.TokenFileErr == nil {
		if err := operations.ConsumeTokenFile(input.TokenFile); err != nil {
			return bootstrap.Material{}, resume, fmt.Errorf("consume enrollment token file: %w", err)
		}
	}
	return material, resume, nil
}

func completeBootstrapCLIResume(ctx context.Context, stateRoot, serverURL string, material bootstrap.Material, resume *bootstrap.ResumeRecord, install func(context.Context, *bootstrap.ClientSession, string) error, save func(string, bootstrap.ResumeRecord) error) error {
	if resume == nil || install == nil || save == nil {
		return bootstrap.ErrResumeBinding
	}
	if !shouldInstallBootstrapCLI(material) || resume.ClientInstalled {
		return nil
	}
	if err := install(ctx, material.ClientSession, serverURL); err != nil {
		return err
	}
	resume.ClientInstalled = true
	if err := save(stateRoot, *resume); err != nil {
		return err
	}
	return nil
}

// recoverAuthenticatedSetupMaterial is intentionally recovery-only. An
// authenticated Host setup has already created and approved its exact pairing
// on the server, so falling back to CreatePairing would discard that authority
// binding and create an unrelated unauthenticated pairing.
func recoverAuthenticatedSetupMaterial(ctx context.Context, config bootstrap.Config, resume bootstrap.ResumeRecord, resumeExpired bool, operations oneShotResumeOperations) (bootstrap.Material, error) {
	if !resume.AuthenticatedSetup || operations.RecoverMaterial == nil {
		return bootstrap.Material{}, bootstrap.ErrResumeBinding
	}
	material, err := operations.RecoverMaterial(ctx, config, resume.RuntimeEnrolled)
	if err != nil {
		if resumeExpired && errors.Is(err, bootstrap.ErrInstallationUnavailable) {
			return bootstrap.Material{}, bootstrap.ErrResumeExpired
		}
		return bootstrap.Material{}, err
	}
	if err := bootstrap.ValidateAuthenticatedSetupMaterial(resume, material); err != nil {
		return bootstrap.Material{}, err
	}
	return material, nil
}

func sameDurableClientSession(previous, recovered *bootstrap.ClientSession) bool {
	if previous == nil || recovered == nil {
		return previous == nil && recovered == nil
	}
	return previous.SessionID == recovered.SessionID &&
		previous.RefreshToken == recovered.RefreshToken &&
		previous.TokenType == recovered.TokenType &&
		strings.TrimSpace(previous.Scope) == strings.TrimSpace(recovered.Scope)
}

func validateOneShotResumeOperations(operations oneShotResumeOperations) error {
	if operations.Now == nil || operations.NewVerifier == nil || operations.SaveResume == nil || operations.ClearResume == nil || operations.CreatePairing == nil || operations.WaitForMaterial == nil || operations.RecoverMaterial == nil || operations.ConsumeTokenFile == nil {
		return bootstrap.ErrResumeBinding
	}
	return nil
}

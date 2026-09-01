package workerupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

// HostdFailureDomainSource resolves the failure domain from the current
// authenticated hostd carrier binding. It does not accept a domain from the
// updater, environment, release index, or a stale cache.
type HostdFailureDomainSource struct {
	Client    HostdUpdateGateClient
	MachineID string
}

func (s HostdFailureDomainSource) ResolveFailureDomain(ctx context.Context, request FailureDomainRequest) (string, error) {
	if ctx == nil || s.Client == nil || !releasepolicy.IsIdentifier(s.MachineID) || request.MachineID != s.MachineID || !releasepolicy.IsIdentifier(request.MachineID) || !releasepolicy.IsVersion(request.Version) || !releasepolicy.IsDigest(request.ManifestSHA256) || !releasepolicy.IsDigest(request.PlanSHA256) || !releasepolicy.IsPlatform(request.Platform, request.Architecture) || request.ReleaseID == "" {
		return "", ErrFailureDomainUnavailable
	}
	transactionID := eligibilityTransactionID(request)
	response, err := s.Client.UpdateGate(ctx, hostdproto.UpdateGateRequest{Operation: hostdproto.UpdateGateTarget, TransactionID: transactionID, Version: request.Version, ManifestSHA256: request.ManifestSHA256})
	if err != nil {
		return "", errors.Join(ErrFailureDomainUnavailable, err)
	}
	target, err := deploymentTargetFromHostd(response.Target)
	if err != nil || target.MachineID != request.MachineID || !releasepolicy.IsIdentifier(target.FailureDomain) {
		return "", errors.Join(ErrFailureDomainUnavailable, err)
	}
	return target.FailureDomain, nil
}

func eligibilityTransactionID(request FailureDomainRequest) string {
	digest := sha256.Sum256([]byte(request.ReleaseID + "\x00" + request.Version + "\x00" + request.ManifestSHA256 + "\x00" + request.PlanSHA256 + "\x00" + request.MachineID + "\x00" + request.Platform + "\x00" + request.Architecture))
	return "eligibility_" + hex.EncodeToString(digest[:16])
}

var _ FailureDomainSource = HostdFailureDomainSource{}

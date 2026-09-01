//go:build windows

package updated

import (
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func windowsCandidateWorkerID(version string) string {
	return "runtime-" + strings.ReplaceAll(version, " ", "-")
}

func windowsCandidateGateRequest(journal windowsActivationJournal, status hostdproto.Status) (workerupdate.GateRequest, error) {
	candidate := windowsCandidateRelease(journal)
	if status.State != hostdproto.StateCandidate || status.WorkerID != windowsCandidateWorkerID(journal.Version) || status.Epoch == 0 || status.APIVersion < candidate.HostdAPIMin || status.APIVersion > candidate.HostdAPIMax {
		return workerupdate.GateRequest{}, errInvalidWindowsActivation
	}
	return workerupdate.GateRequest{TransactionID: journal.TransactionID, Previous: windowsPreviousRelease(journal), Candidate: candidate, Worker: status}, nil
}

func windowsDrainGateRequest(journal windowsActivationJournal, status hostdproto.Status) (workerupdate.GateRequest, error) {
	request, err := windowsCandidateGateRequest(journal, status)
	if err != nil {
		return workerupdate.GateRequest{}, err
	}
	return request, nil
}

func windowsActiveGateRequest(journal windowsActivationJournal, status hostdproto.Status) (workerupdate.GateRequest, error) {
	candidate := windowsCandidateRelease(journal)
	if status.State != hostdproto.StateActive || status.WorkerID != windowsCandidateWorkerID(journal.Version) || status.Epoch == 0 || status.APIVersion < candidate.HostdAPIMin || status.APIVersion > candidate.HostdAPIMax {
		return workerupdate.GateRequest{}, errInvalidWindowsActivation
	}
	return workerupdate.GateRequest{TransactionID: journal.TransactionID, Previous: windowsPreviousRelease(journal), Candidate: candidate, Worker: status, Window: journal.StabilityWindow, Interval: journal.StabilityInterval}, nil
}

func windowsRollbackGateRequest(journal windowsActivationJournal, status hostdproto.Status) (workerupdate.GateRequest, error) {
	if status.State != hostdproto.StateActive || status.WorkerID != windowsCandidateWorkerID(journal.PreviousVersion) || status.Epoch == 0 || status.APIVersion == 0 {
		return workerupdate.GateRequest{}, errInvalidWindowsActivation
	}
	return workerupdate.GateRequest{TransactionID: journal.TransactionID, Previous: windowsCandidateRelease(journal), Candidate: windowsPreviousRelease(journal), Worker: status}, nil
}

func windowsPreviousRelease(j windowsActivationJournal) workerupdate.Release {
	return workerupdate.Release{Version: j.PreviousVersion, SHA256: j.PreviousBinary.SHA256, Length: j.PreviousBinary.Length, Platform: "windows", Architecture: j.Architecture, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2}
}

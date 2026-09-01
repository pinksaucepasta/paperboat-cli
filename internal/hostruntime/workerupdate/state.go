package workerupdate

import (
	"os"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/updateflow"
)

const TransactionSchemaV1 = "paperboat.update-transaction/v1"

// TransactionState is the bounded safe projection used by local status,
// diagnostics, and lifecycle events. It never exposes paths, capabilities, or
// artifact URLs.
type TransactionState struct {
	Schema           string             `json:"schema,omitempty"`
	TransactionID    string             `json:"transaction_id,omitempty"`
	Stage            updateflow.Stage   `json:"stage,omitempty"`
	ActiveVersion    string             `json:"active_version,omitempty"`
	CandidateVersion string             `json:"candidate_version,omitempty"`
	Failure          updateflow.Failure `json:"failure,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at,omitempty"`
	HealthDeadline   time.Time          `json:"health_deadline,omitempty"`
	RollbackCount    uint32             `json:"rollback_count,omitempty"`
	Quarantined      bool               `json:"quarantined,omitempty"`
}

func (m *Manager) TransactionState() (TransactionState, error) {
	if m == nil {
		return TransactionState{}, ErrInvalidConfig
	}
	journal, err := updateflow.Load(m.config.StatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return TransactionState{Schema: TransactionSchemaV1, Stage: updateflow.StageIdle, ActiveVersion: m.ActiveVersion()}, nil
		}
		return TransactionState{}, err
	}
	return TransactionState{
		Schema: TransactionSchemaV1, TransactionID: journal.TransactionID, Stage: journal.Stage,
		ActiveVersion: journal.ActiveVersion, CandidateVersion: journal.CandidateVersion,
		Failure: journal.LastFailure, UpdatedAt: journal.StageUpdatedAt,
		HealthDeadline: journal.HealthDeadline, RollbackCount: journal.RollbackCount,
		Quarantined: journal.Stage == updateflow.StageIdle && journal.CandidateVersion != "" && journal.LastFailure != updateflow.FailureNone,
	}, nil
}

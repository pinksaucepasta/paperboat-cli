package networkadaptation

import "github.com/pinksaucepasta/paperboat/internal/peertransport/peerquic"

// ApplyLifetimeDecision applies a conservative mapping-lifetime decision to a
// new QUIC session. Existing connections are deliberately left unchanged.
func ApplyLifetimeDecision(config peerquic.SessionConfig, decision LifetimeDecision) (peerquic.SessionConfig, error) {
	if decision.Interval <= 0 {
		return peerquic.SessionConfig{}, ErrInvalid
	}
	return config.WithKeepAlive(decision.Interval)
}

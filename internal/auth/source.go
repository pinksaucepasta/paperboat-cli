package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/api"
	"github.com/pujan-modha/paperboat-cli/internal/config"
)

const refreshBefore = 60 * time.Second

type Source struct {
	Store  config.ProfileStore
	Issuer string
}

func NewSource(cfg *config.Config) (*Source, error) {
	store, err := config.ProfileStoreFor(cfg)
	if err != nil {
		return nil, err
	}
	return &Source{Store: store, Issuer: cfg.ServerURL}, nil
}

func (s *Source) Credential() (config.Credential, error) {
	return s.credential(refreshBefore)
}

func (s *Source) Refresh() (config.Credential, error) {
	return s.credential(100 * 365 * 24 * time.Hour)
}

func (s *Source) credential(refreshWindow time.Duration) (config.Credential, error) {
	return s.Store.CredentialWithRefresh(s.Issuer, refreshWindow, func(current config.Credential) (config.Credential, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tokens, err := api.RefreshToken(ctx, s.Issuer, current.RefreshToken, nil)
		if err != nil {
			return config.Credential{}, "", fmt.Errorf("refresh Paperboat session: %w", err)
		}
		expires := time.Now().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		return config.Credential{AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, TokenType: tokens.TokenType, ExpiresAt: expires}, tokens.ClientSessionID, nil
	})
}

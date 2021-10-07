package tokenprovider

import (
	"context"

	"golang.org/x/oauth2/google"
)

// NewGceAccessTokenProvider returns a token provider for gce authentication
func NewGceAccessTokenProvider(ctx context.Context, cfg *Config) (TokenProvider, error) {
	source, err := google.DefaultTokenSource(ctx, cfg.Scopes...)
	if err != nil {
		return nil, err
	}

	return &tokenProviderImpl{
		cacheKey:    createCacheKey("gce", cfg),
		tokenSource: source,
	}, nil
}

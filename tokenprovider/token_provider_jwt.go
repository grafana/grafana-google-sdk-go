package tokenprovider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

// NewJwtAccessTokenProvider returns a token provider for jwt file authentication
func NewJwtAccessTokenProvider(ctx context.Context, cfg *Config) TokenProvider {
	conf := &jwt.Config{
		Email:      cfg.JwtTokenConfig.Email,
		PrivateKey: cfg.JwtTokenConfig.PrivateKey,
		TokenURL:   cfg.JwtTokenConfig.URI,
		Scopes:     cfg.Scopes,
	}

	return &tokenProviderImpl{
		cacheKey:    createCacheKey("jwt", cfg),
		tokenSource: getTokenSource(ctx, conf),
	}
}

// getTokenSource returns a TokenSource.
// Stubbable by tests.
var getTokenSource = func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
	return conf.TokenSource(ctx)
}

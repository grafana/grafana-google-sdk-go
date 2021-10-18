package tokenprovider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

type jwtSource struct {
	cacheKey string
	conf     jwt.Config
}

// NewJwtAccessTokenProvider returns a token provider for jwt file authentication
func NewJwtAccessTokenProvider(cfg Config) TokenProvider {
	return &tokenProviderImpl{
		&jwtSource{
			cacheKey: createCacheKey("jwt", &cfg),
			conf: jwt.Config{
				Email:      cfg.JwtTokenConfig.Email,
				PrivateKey: cfg.JwtTokenConfig.PrivateKey,
				TokenURL:   cfg.JwtTokenConfig.URI,
				Scopes:     cfg.Scopes,
			},
		},
	}
}

func (source *jwtSource) getCacheKey() string {
	return source.cacheKey
}

func (source *jwtSource) getToken(ctx context.Context) (*oauth2.Token, error) {
	return getTokenSource(ctx, &source.conf).Token()
}

// getTokenSource returns a TokenSource.
// Stubbable by tests.
var getTokenSource = func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
	return conf.TokenSource(ctx)
}

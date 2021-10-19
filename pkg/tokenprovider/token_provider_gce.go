package tokenprovider

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type gceSource struct {
	cacheKey string
	scopes   []string
}

// NewGceAccessTokenProvider returns a token provider for gce authentication
func NewGceAccessTokenProvider(cfg Config) TokenProvider {
	return &tokenProviderImpl{
		&gceSource{
			cacheKey: createCacheKey("gce", &cfg),
			scopes:   cfg.Scopes,
		},
	}
}

func (source *gceSource) getCacheKey() string {
	return source.cacheKey
}

func (source *gceSource) getToken(ctx context.Context) (*oauth2.Token, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, source.scopes...)
	if err != nil {
		return nil, err
	}
	return tokenSource.Token()
}

package tokenprovider

import (
	"context"
	"log"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
)

type gceSource struct {
	cacheKey string
	scopes   []string
}

type impersonatedGceSource struct {
	cacheKey        string
	scopes          []string
	TargetPrincipal string
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

func NewImpersonatedGceAccessTokenProvider(cfg Config) TokenProvider {
	return &tokenProviderImpl{
		&impersonatedGceSource{
			cacheKey:        createCacheKey("gce", &cfg),
			scopes:          cfg.Scopes,
			TargetPrincipal: cfg.TargetPrincipal,
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

func (source *impersonatedGceSource) getCacheKey() string {
	return source.cacheKey
}

func (source *impersonatedGceSource) getToken(ctx context.Context) (*oauth2.Token, error) {
	tokenSource, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: source.TargetPrincipal,
		Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
	})
	if err != nil {
		log.Fatal(err)
	}
	return tokenSource.Token()
}

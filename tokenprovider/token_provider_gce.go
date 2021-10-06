package tokenprovider

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/google"
)

// gceAccessTokenProvider implements TokenRetriever for gce authentication
type gceAccessTokenProvider struct {
	cacheKey string
}

// NewGceAccessTokenProvider returns a token provider for gce authentication
func NewGceAccessTokenProvider(dsID int64, dsVersion int) GoogleTokenProvider {
	gceRetriever := &gceAccessTokenProvider{
		cacheKey: fmt.Sprintf("%v_%v_%v", dsID, dsVersion, "gce"),
	}
	return &tokenProviderImpl{gceRetriever}
}

// GetAccessToken implements TokenRetriever
func (provider *gceAccessTokenProvider) GetAccessToken(ctx context.Context, scopes []string) (*AccessToken, error) {
	tokenSrc, err := google.DefaultTokenSource(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	token, err := tokenSrc.Token()
	if err != nil {
		return nil, err
	}
	return &AccessToken{Token: token.AccessToken, ExpiresOn: token.Expiry}, nil
}

// GetCacheKey implements TokenRetriever
func (provider *gceAccessTokenProvider) GetCacheKey() string {
	return provider.cacheKey
}
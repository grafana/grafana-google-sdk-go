package tokenprovider

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

// jwtAccessTokenProvider implements TokenRetriever for jwt file authentication
type jwtAccessTokenProvider struct {
	cacheKey   string
	email      string
	privateKey []byte
	tokenURL   string
}

// NewJwtAccessTokenProvider returns a token provider for jwt file authentication
func NewJwtAccessTokenProvider(cfg *Config) TokenProvider {
	key := fmt.Sprintf("jwt_%v_%v_%v_%v", cfg.DataSourceID, cfg.DataSourceVersion, cfg.RoutePath, cfg.RouteMethod)
	jwtRetriever := &jwtAccessTokenProvider{
		cacheKey:   key,
		email:      cfg.JwtTokenConfig.Email,
		privateKey: cfg.JwtTokenConfig.PrivateKey,
		tokenURL:   cfg.JwtTokenConfig.URI,
	}
	return &tokenProviderImpl{jwtRetriever}
}

// GetAccessToken implements TokenRetriever
func (provider *jwtAccessTokenProvider) GetAccessToken(ctx context.Context, scopes []string) (*AccessToken, error) {
	conf := &jwt.Config{
		Email:      provider.email,
		PrivateKey: provider.privateKey,
		TokenURL:   provider.tokenURL,
		Scopes:     scopes,
	}

	token, err := getToken(ctx, conf)
	if err != nil {
		return nil, err
	}

	return &AccessToken{Token: token.AccessToken, ExpiresOn: token.Expiry}, nil
}

// getToken returns a token.
// Stubbable by tests.
var getToken = func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
	return conf.TokenSource(ctx).Token()
}

// GetCacheKey implements TokenRetriever
func (provider *jwtAccessTokenProvider) GetCacheKey() string {
	return provider.cacheKey
}

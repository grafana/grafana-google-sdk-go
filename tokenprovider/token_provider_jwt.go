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
	authParams *JwtTokenAuth
	email      string
	privateKey []byte
	tokenURL   string
}

// NewJwtAccessTokenProvider returns a token provider for jwt file authentication
func NewJwtAccessTokenProvider(dsID int64, dsVersion int, pluginRoute *AppPluginRoute,
	authParams *JwtTokenAuth) GoogleTokenProvider {
	jwtRetriever := &jwtAccessTokenProvider{
		cacheKey:   fmt.Sprintf("%v_%v_%v_%v", dsID, dsVersion, pluginRoute.Path, pluginRoute.Method),
		authParams: authParams,
	}
	if val, ok := authParams.Params["client_email"]; ok {
		jwtRetriever.email = val
	}

	if val, ok := authParams.Params["private_key"]; ok {
		jwtRetriever.privateKey = []byte(val)
	}

	if val, ok := authParams.Params["token_uri"]; ok {
		jwtRetriever.tokenURL = val
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

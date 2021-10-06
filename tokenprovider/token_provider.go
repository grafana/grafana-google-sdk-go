package tokenprovider

import (
	"context"
	"fmt"
)

var (
	googleTokenCache = NewConcurrentTokenCache()
)

// GoogleTokenProvider is anything that can return a token
type GoogleTokenProvider interface {
	GetAccessToken(ctx context.Context, scope []string) (string, error)
}

type tokenProviderImpl struct {
	tokenRetriever TokenRetriever
}

// GetAccessToken implements GoogleTokenProvider
func (provider *tokenProviderImpl) GetAccessToken(ctx context.Context, scopes []string) (string, error) {
	if ctx == nil {
		err := fmt.Errorf("parameter 'ctx' cannot be nil")
		return "", err
	}

	accessToken, err := googleTokenCache.GetAccessToken(ctx, provider.tokenRetriever, scopes)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

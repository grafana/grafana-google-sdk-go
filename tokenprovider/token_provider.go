package tokenprovider

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

var (
	tokenCache = oauthTokenCacheType{
		cache: map[string]*oauth2.Token{},
	}

	// timeNow makes it possible to test usage of time
	timeNow = time.Now
)

type oauthTokenCacheType struct {
	cache map[string]*oauth2.Token
	sync.Mutex
}

// TokenProvider is anything that can return a token
type TokenProvider interface {
	GetAccessToken() (string, error)
}

// tokenProviderImpl implements the TokenProvider interface
type tokenProviderImpl struct {
	cacheKey    string
	tokenSource oauth2.TokenSource
}

// GetAccessToken implements TokenProvider
func (tpi *tokenProviderImpl) GetAccessToken() (string, error) {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	if cachedToken, found := tokenCache.cache[tpi.cacheKey]; found {
		if cachedToken.Expiry.After(timeNow().Add(time.Second * 10)) {
			return cachedToken.AccessToken, nil
		}
	}
	token, err := tpi.tokenSource.Token()
	if err != nil {
		return "", err
	}

	tokenCache.cache[tpi.cacheKey] = token
	return token.AccessToken, nil
}

func createCacheKey(authtype string, cfg *Config) string {
	key := fmt.Sprintf("%v_%v_%v_%v_%v", authtype, cfg.DataSourceID, cfg.DataSourceVersion, cfg.RoutePath, cfg.RouteMethod)
	if len(cfg.Scopes) == 0 {
		return key
	}

	arr := make([]string, len(cfg.Scopes))
	copy(arr, cfg.Scopes)
	sort.Strings(arr)
	return fmt.Sprintf("%v_%v", key, strings.Join(arr, "-"))
}

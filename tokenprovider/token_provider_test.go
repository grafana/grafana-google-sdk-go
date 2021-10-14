package tokenprovider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

type fakeTokenSource struct {
	tokens []string
	index  int
}

func (fts *fakeTokenSource) Token() (*oauth2.Token, error) {
	defer func() {
		fts.index += 1
	}()

	if fts.index >= len(fts.tokens) || fts.tokens[fts.index] == "" {
		return nil, fmt.Errorf("failed")
	}
	return &oauth2.Token{
		AccessToken: fts.tokens[fts.index],
		Expiry:      timeNow().Add(1 * time.Minute),
	}, nil
}

func TestCreateCacheKey(t *testing.T) {
	config := &Config{
		RoutePath:         "path",
		RouteMethod:       "GET",
		DataSourceID:      1,
		DataSourceUpdated: time.Now(),
		Scopes: []string{
			"scope1",
			"scope2",
		},
	}

	expectedKey := fmt.Sprintf("gce_1_%v_path_GET_scope1-scope2", config.DataSourceUpdated.Unix())
	actualKey := createCacheKey("gce", config)
	assert.Equal(t, expectedKey, actualKey)
}

func TestJwtTokenProvider(t *testing.T) {
	config := &Config{
		RoutePath:         "pathwithjwttoken1",
		RouteMethod:       "GET",
		DataSourceID:      1,
		DataSourceUpdated: time.Now(),
		Scopes: []string{
			"https://www.testapi.com/auth/monitoring.read",
			"https://www.testapi.com/auth/cloudplatformprojects.readonly",
		},
		JwtTokenConfig: &JwtTokenConfig{
			Email:      "test@test.com",
			PrivateKey: []byte("testkey"),
			URI:        "login.url.com/token",
		},
	}

	setUp := func(t *testing.T, fn func(context.Context, *jwt.Config) oauth2.TokenSource) {
		origFn := getTokenSource
		t.Cleanup(func() {
			getTokenSource = origFn
		})

		getTokenSource = fn
	}

	changeTime := func(t *testing.T, fn func() time.Time) {
		origFn := timeNow
		t.Cleanup(func() {
			timeNow = origFn
		})

		timeNow = fn
	}

	t.Run("should set JWT config values", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			assert.Equal(t, "test@test.com", conf.Email)
			assert.Equal(t, []byte("testkey"), conf.PrivateKey)
			assert.Equal(t, 2, len(conf.Scopes))
			assert.Equal(t, "https://www.testapi.com/auth/monitoring.read", conf.Scopes[0])
			assert.Equal(t, "https://www.testapi.com/auth/cloudplatformprojects.readonly", conf.Scopes[1])
			assert.Equal(t, "login.url.com/token", conf.TokenURL)

			return &fakeTokenSource{tokens: []string{"abc"}}
		})

		provider := NewJwtAccessTokenProvider(context.Background(), config)
		token, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token)
	})

	t.Run("should use cached token on second call", func(t *testing.T) {
		clearTokenCache()
		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"abc", ""}}
		})
		provider := NewJwtAccessTokenProvider(context.Background(), config)
		token1, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		token2, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token2)
	})

	t.Run("should not use expired cached token", func(t *testing.T) {
		clearTokenCache()
		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"abc", "def"}}
		})
		provider := NewJwtAccessTokenProvider(context.Background(), config)
		token1, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		changeTime(t, func() time.Time {
			return time.Now().Add(time.Hour)
		})
		token2, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "def", token2)
	})

	t.Run("should use cached token for same config", func(t *testing.T) {
		clearTokenCache()
		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"abc"}}
		})
		provider1 := NewJwtAccessTokenProvider(context.Background(), config)
		token1, err := provider1.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"xyz"}}
		})
		provider2 := NewJwtAccessTokenProvider(context.Background(), config)
		token2, err := provider2.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token2)
	})

	t.Run("should not use cache for different scope", func(t *testing.T) {
		clearTokenCache()
		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"abc", "def"}}
		})
		config.Scopes = []string{"scope1"}
		provider := NewJwtAccessTokenProvider(context.Background(), config)
		token1, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		setUp(t, func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
			return &fakeTokenSource{tokens: []string{"xyz"}}
		})
		config.Scopes = []string{"scope2"}
		provider = NewJwtAccessTokenProvider(context.Background(), config)
		token2, err := provider.GetAccessToken()
		require.NoError(t, err)
		assert.Equal(t, "xyz", token2)
	})
}

func clearTokenCache() {
	tokenCache.Lock()
	defer tokenCache.Unlock()
	tokenCache.cache = map[string]*oauth2.Token{}
}

package tokenprovider

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

func TestAccessToken_pluginWithJWTTokenAuthRoute(t *testing.T) {
	config := &Config{
		RoutePath:         "pathwithjwttoken1",
		RouteMethod:       "GET",
		DataSourceID:      1,
		DataSourceVersion: 2,
		JwtTokenConfig: &JwtTokenConfig{
			Email:      "test@test.com",
			PrivateKey: []byte("testkey"),
			URI:        "login.url.com/token",
		},
	}
	scopes := []string{
		"https://www.testapi.com/auth/monitoring.read",
		"https://www.testapi.com/auth/cloudplatformprojects.readonly",
	}

	setUp := func(t *testing.T, fn func(context.Context, *jwt.Config) (*oauth2.Token, error)) {
		origFn := getToken
		t.Cleanup(func() {
			getToken = origFn
		})

		getToken = fn
	}

	t.Run("should fetch token using JWT private key", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "abc"}, nil
		})
		provider := NewJwtAccessTokenProvider(config)
		token, err := provider.GetAccessToken(context.Background(), scopes)
		require.NoError(t, err)

		assert.Equal(t, "abc", token)
	})

	t.Run("should set JWT config values", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			assert.Equal(t, "test@test.com", conf.Email)
			assert.Equal(t, []byte("testkey"), conf.PrivateKey)
			assert.Equal(t, 2, len(conf.Scopes))
			assert.Equal(t, "https://www.testapi.com/auth/monitoring.read", conf.Scopes[0])
			assert.Equal(t, "https://www.testapi.com/auth/cloudplatformprojects.readonly", conf.Scopes[1])
			assert.Equal(t, "login.url.com/token", conf.TokenURL)

			return &oauth2.Token{AccessToken: "abc"}, nil
		})

		provider := NewJwtAccessTokenProvider(config)
		_, err := provider.GetAccessToken(context.Background(), scopes)
		require.NoError(t, err)
	})

	t.Run("should use cached token on second call", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken: "abc",
				Expiry:      time.Now().Add(1 * time.Minute)}, nil
		})
		provider := NewJwtAccessTokenProvider(config)
		token1, err := provider.GetAccessToken(context.Background(), scopes)
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		getToken = func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "error: cache not used"}, nil
		}
		token2, err := provider.GetAccessToken(context.Background(), scopes)
		require.NoError(t, err)
		assert.Equal(t, "abc", token2)
	})
}

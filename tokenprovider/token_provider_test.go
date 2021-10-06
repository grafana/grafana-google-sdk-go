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
	pluginRoute := &AppPluginRoute{
		Path:   "pathwithjwttoken1",
		URL:    "https://api.jwt.io/some/path",
		Method: "GET",
		JwtTokenAuth: &JwtTokenAuth{
			Url: "https://login.server.com/{{.JsonData.tenantId}}/oauth2/token",
			Scopes: []string{
				"https://www.testapi.com/auth/monitoring.read",
				"https://www.testapi.com/auth/cloudplatformprojects.readonly",
			},
			Params: map[string]string{
				"token_uri":    "{{.JsonData.tokenUri}}",
				"client_email": "{{.JsonData.clientEmail}}",
				"private_key":  "{{.SecureJsonData.privateKey}}",
			},
		},
	}

	authParams := &JwtTokenAuth{
		Url: "https://login.server.com/{{.JsonData.tenantId}}/oauth2/token",
		Scopes: []string{
			"https://www.testapi.com/auth/monitoring.read",
			"https://www.testapi.com/auth/cloudplatformprojects.readonly",
		},
		Params: map[string]string{
			"token_uri":    "login.url.com/token",
			"client_email": "test@test.com",
			"private_key":  "testkey",
		},
	}

	setUp := func(t *testing.T, fn func(context.Context, *jwt.Config) (*oauth2.Token, error)) {
		origFn := getToken
		t.Cleanup(func() {
			getToken = origFn
		})

		getToken = fn
	}

	dsId := int64(1)
	dsVersion := 2

	t.Run("should fetch token using JWT private key", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "abc"}, nil
		})
		provider := NewJwtAccessTokenProvider(dsId, dsVersion, pluginRoute, authParams)
		token, err := provider.GetAccessToken(context.Background(), authParams.Scopes)
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

		provider := NewJwtAccessTokenProvider(dsId, dsVersion, pluginRoute, authParams)
		_, err := provider.GetAccessToken(context.Background(), authParams.Scopes)
		require.NoError(t, err)
	})

	t.Run("should use cached token on second call", func(t *testing.T) {
		setUp(t, func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken: "abc",
				Expiry:      time.Now().Add(1 * time.Minute)}, nil
		})
		provider := NewJwtAccessTokenProvider(dsId, dsVersion, pluginRoute, authParams)
		token1, err := provider.GetAccessToken(context.Background(), authParams.Scopes)
		require.NoError(t, err)
		assert.Equal(t, "abc", token1)

		getToken = func(ctx context.Context, conf *jwt.Config) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "error: cache not used"}, nil
		}
		token2, err := provider.GetAccessToken(context.Background(), authParams.Scopes)
		require.NoError(t, err)
		assert.Equal(t, "abc", token2)
	})
}

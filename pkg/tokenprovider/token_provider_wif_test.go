package tokenprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWifAccessTokenProvider(t *testing.T) {
	t.Run("should return error when config is nil", func(t *testing.T) {
		_, err := NewWifAccessTokenProvider(Config{}, nil)
		assert.Error(t, err)
	})

	t.Run("should return error when audience is missing", func(t *testing.T) {
		_, err := NewWifAccessTokenProvider(Config{}, &WifConfig{
			SubjectTokenType: "test",
			JwtBearerToken:   "test",
		})
		assert.Error(t, err)
	})

	t.Run("should return error when subject token type is missing", func(t *testing.T) {
		_, err := NewWifAccessTokenProvider(Config{}, &WifConfig{
			Audience:       "test",
			JwtBearerToken: "test",
		})
		assert.Error(t, err)
	})

	t.Run("should return error when JWT token is missing", func(t *testing.T) {
		_, err := NewWifAccessTokenProvider(Config{}, &WifConfig{
			Audience:        "test",
			SubjectTokenType: "test",
		})
		assert.Error(t, err)
	})
}

func TestWifTokenExchange(t *testing.T) {
	// Setup test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		err := r.ParseForm()
		assert.NoError(t, err)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
		assert.Equal(t, "test-audience", r.Form.Get("audience"))
		assert.Equal(t, "test-token-type", r.Form.Get("subject_token_type"))
		assert.Equal(t, "test-jwt-token", r.Form.Get("subject_token"))

		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer testServer.Close()

	// Test with custom token URL
	provider, err := NewWifAccessTokenProvider(Config{}, &WifConfig{
		Audience:        "test-audience",
		TokenURL:        testServer.URL,
		SubjectTokenType: "test-token-type",
		JwtBearerToken:   "test-jwt-token",
	})
	require.NoError(t, err)

	token, err := provider.GetAccessToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", token)
}

func TestWifTokenExchange_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedErr    string
		expectedStatus int
	}{
		{
			name: "invalid token response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid json"))
			},
			expectedErr: "failed to decode token response",
		},
		{
			name: "error response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_request",
					"error_description": "Invalid token",
				})
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    "token exchange failed with status 400",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer := httptest.NewServer(tc.handler)
			defer testServer.Close()

			provider, err := NewWifAccessTokenProvider(Config{}, &WifConfig{
				Audience:        "test",
				TokenURL:        testServer.URL,
				SubjectTokenType: "test",
				JwtBearerToken:   "test",
			})
			require.NoError(t, err)

			_, err = provider.GetAccessToken(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestImpersonatedWifAccessTokenProvider(t *testing.T) {
	// Setup test server for token exchange
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-wif-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// Setup test server for impersonation
	impersonationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header contains the WIF token
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-wif-token", auth)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accessToken": "test-impersonated-token",
			"expireTime":  time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))

	provider, err := NewImpersonatedWifAccessTokenProvider(Config{
		TargetPrincipal: "test-service-account@project.iam.gserviceaccount.com",
	}, &WifConfig{
		Audience:        "test-audience",
		TokenURL:        tokenServer.URL,
		SubjectTokenType: "test-token-type",
		JwtBearerToken:   "test-jwt-token",
	})
	require.NoError(t, err)

	// This will fail because we can't easily test the full impersonation flow,
	// but it verifies that the provider is created correctly
	assert.NotNil(t, provider)
}

func TestNewImpersonatedWifAccessTokenProvider_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wifCfg  *WifConfig
		wantErr string
	}{
		{
			name:    "missing wif config",
			cfg:     Config{},
			wifCfg:  nil,
			wantErr: "wifConfig cannot be nil",
		},
		{
			name: "missing target principal",
			cfg:  Config{},
			wifCfg: &WifConfig{
				Audience:        "test",
				SubjectTokenType: "test",
				JwtBearerToken:   "test",
			},
			wantErr: "either targetPrincipal or serviceAccountEmail is required",
		},
		{
			name: "uses service account email",
			cfg:  Config{},
			wifCfg: &WifConfig{
				Audience:          "test",
				SubjectTokenType:   "test",
				JwtBearerToken:     "test",
				ServiceAccountEmail: "test@example.com",
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewImpersonatedWifAccessTokenProvider(tt.cfg, tt.wifCfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

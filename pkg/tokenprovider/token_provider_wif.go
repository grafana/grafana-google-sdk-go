/*
Package tokenprovider implements token providers for various authentication methods,
including Workload Identity Federation (WIF) with JWT bearer token flow.
*/
package tokenprovider

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"

    "golang.org/x/oauth2"
    "google.golang.org/api/impersonate"
    "google.golang.org/api/option"
)

// WifConfig contains configuration for Workload Identity Federation authentication.
// It supports JWT bearer token flow with optional service account impersonation.
type WifConfig struct {
    // Audience is the intended audience of the token, typically in the format:
    // //iam.googleapis.com/projects/{project-number}/locations/global/workloadIdentityPools/{pool-id}/providers/{provider-id}
    Audience string `json:"audience"`

    // TokenURL is the STS token exchange endpoint URL.
    // Defaults to "https://sts.googleapis.com/v1/token" if empty.
    TokenURL string `json:"tokenUrl"`

    // SubjectTokenType is the type of the subject token being exchanged.
    // Example: "urn:ietf:params:oauth:token-type:jwt"
    SubjectTokenType string `json:"subjectTokenType"`

    // JwtBearerToken is the JWT token to use as credential source for the token exchange.
    JwtBearerToken string `json:"jwtBearerToken"`

    // ServiceAccountImpersonationURL is the URL for service account impersonation.
    // If provided, the token will be used to impersonate the target service account.
    ServiceAccountImpersonationURL string `json:"serviceAccountImpersonationUrl,omitempty"`

    // ServiceAccountEmail is the email of the service account to impersonate.
    // This is an alternative to specifying TargetPrincipal in the Config.
    ServiceAccountEmail string `json:"serviceAccountEmail,omitempty"`

    // Claims contains additional claims to include in the token exchange request.
    Claims map[string]string `json:"claims,omitempty"`
}

// wifSource implements tokenSource for Workload Identity Federation.
type wifSource struct {
    cacheKey string
    config   *WifConfig
    scopes   []string
}

// NewWifAccessTokenProvider creates a new TokenProvider that uses Workload Identity Federation
// with the provided configuration. It returns an error if required fields are missing.
//
// Example:
//
//	provider, err := NewWifAccessTokenProvider(Config{...}, &WifConfig{
//	    Audience:        "//iam.googleapis.com/...",
//	    TokenURL:        "https://sts.googleapis.com/v1/token",
//	    SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
//	    JwtBearerToken:  "your.jwt.token",
//	})
func NewWifAccessTokenProvider(cfg Config, wifConfig *WifConfig) (TokenProvider, error) {
    if wifConfig == nil {
        return nil, fmt.Errorf("wifConfig cannot be nil")
    }
    if wifConfig.Audience == "" {
        return nil, fmt.Errorf("audience is required in WIF config")
    }
    if wifConfig.SubjectTokenType == "" {
        return nil, fmt.Errorf("subjectTokenType is required in WIF config")
    }
    if wifConfig.JwtBearerToken == "" {
        return nil, fmt.Errorf("jwtBearerToken is required in WIF config")
    }

    return &tokenProviderImpl{
        &wifSource{
            cacheKey: createCacheKey("wif", &cfg),
            config:   wifConfig,
            scopes:   cfg.Scopes,
        },
    }, nil
}

// getCacheKey returns the cache key for the token source.
func (source *wifSource) getCacheKey() string {
    return source.cacheKey
}

// getToken implements the tokenSource interface.
// It performs the token exchange using the configured JWT bearer token.
func (source *wifSource) getToken(ctx context.Context) (*oauth2.Token, error) {
    if source.config.JwtBearerToken == "" {
        return nil, fmt.Errorf("JWT bearer token is required")
    }

    // Prepare the token exchange request
    tokenURL := source.config.TokenURL
    if tokenURL == "" {
        tokenURL = "https://sts.googleapis.com/v1/token"
    } else {
        if _, err := url.ParseRequestURI(tokenURL); err != nil {
            return nil, fmt.Errorf("invalid token URL: %v", err)
        }
    }

    form := url.Values{
        "grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
        "audience":             {source.config.Audience},
        "subject_token_type":   {source.config.SubjectTokenType},
        "subject_token":        {source.config.JwtBearerToken},
        "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
    }

    if len(source.scopes) > 0 {
        form.Add("scope", strings.Join(append(source.scopes, "https://www.googleapis.com/auth/cloud-platform"), " "))
    }

    // Create a new request with timeout
    reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    req, err := http.NewRequestWithContext(reqCtx, "POST", tokenURL, strings.NewReader(form.Encode()))
    if err != nil {
        return nil, fmt.Errorf("failed to create token request: %v", err)
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    // Execute the token exchange
    httpClient := oauth2.NewClient(ctx, nil)
    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("token exchange request failed: %v", err)
    }
    defer resp.Body.Close()

    // Read the response body first, as we'll need it for both error and success cases
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read token response: %v", err)
    }

    // Handle non-200 status codes
    if resp.StatusCode != http.StatusOK {
        // Try to parse error response if it's JSON
        var errorResp struct {
            Error       string `json:"error"`
            Description string `json:"error_description"`
        }
        if json.Unmarshal(body, &errorResp) == nil && errorResp.Error != "" {
            return nil, fmt.Errorf("token exchange failed with status %d: %s - %s", 
                resp.StatusCode, errorResp.Error, errorResp.Description)
        }
        return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
    }

    // For 200 OK, first verify if the response is valid JSON
    if !json.Valid(body) {
        return nil, fmt.Errorf("failed to decode token response: invalid JSON")
    }

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        TokenType   string `json:"token_type"`
        ExpiresIn   int64  `json:"expires_in"`
        Error       string `json:"error"`
        ErrorDesc   string `json:"error_description"`
    }

    if err := json.Unmarshal(body, &tokenResp); err != nil {
        return nil, fmt.Errorf("failed to decode token response: %v, body: %s", err, string(body))
    }

    if tokenResp.Error != "" {
        return nil, fmt.Errorf("token exchange error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
    }
    
    if tokenResp.AccessToken == "" {
        return nil, fmt.Errorf("token response missing access_token")
    }
    
    if tokenResp.TokenType == "" {
        tokenResp.TokenType = "Bearer"
    }
    
    if tokenResp.ExpiresIn <= 0 {
        return nil, fmt.Errorf("invalid or missing expires_in in token response")
    }

    return &oauth2.Token{
        AccessToken: tokenResp.AccessToken,
        TokenType:   tokenResp.TokenType,
        Expiry:      time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
    }, nil
}

// impersonatedWifSource implements tokenSource for WIF with service account impersonation.
type impersonatedWifSource struct {
    cacheKey        string
    config          *WifConfig
    scopes          []string
    TargetPrincipal string
    Subject         string
    Delegates       []string
}

// NewImpersonatedWifAccessTokenProvider creates a new TokenProvider that uses WIF
// with service account impersonation. It returns an error if required fields are missing.
//
// The provider will first exchange the JWT bearer token for a Google access token,
// then use that token to impersonate the target service account.
func NewImpersonatedWifAccessTokenProvider(cfg Config, wifConfig *WifConfig) (TokenProvider, error) {
    if wifConfig == nil {
        return nil, fmt.Errorf("wifConfig cannot be nil")
    }
    if wifConfig.Audience == "" {
        return nil, fmt.Errorf("audience is required in WIF config")
    }
    if wifConfig.SubjectTokenType == "" {
        return nil, fmt.Errorf("subjectTokenType is required in WIF config")
    }
    if wifConfig.JwtBearerToken == "" {
        return nil, fmt.Errorf("jwtBearerToken is required in WIF config")
    }
    if cfg.TargetPrincipal == "" && wifConfig.ServiceAccountEmail == "" {
        return nil, fmt.Errorf("either targetPrincipal or serviceAccountEmail is required for impersonation")
    }
    
    if cfg.TargetPrincipal == "" && wifConfig.ServiceAccountEmail != "" {
        cfg.TargetPrincipal = wifConfig.ServiceAccountEmail
    }

    return &tokenProviderImpl{
        &impersonatedWifSource{
            cacheKey:        createCacheKey("wif", &cfg),
            config:          wifConfig,
            scopes:          append(cfg.Scopes, "https://www.googleapis.com/auth/cloud-platform"),
            TargetPrincipal: cfg.TargetPrincipal,
            Subject:         cfg.Subject,
            Delegates:       cfg.Delegates,
        },
    }, nil
}

// getCacheKey returns the cache key for the token source.
func (source *impersonatedWifSource) getCacheKey() string {
    return source.cacheKey
}

// getToken implements the tokenSource interface for impersonated WIF.
// It first gets a token using WIF, then uses it to impersonate the target service account.
func (source *impersonatedWifSource) getToken(ctx context.Context) (*oauth2.Token, error) {
    // First get a WIF token
    wifToken, err := (&wifSource{
        config: source.config,
        scopes: source.scopes,
    }).getToken(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get WIF token: %v", err)
    }

    // Create a token source with the WIF token
    tokenSource := oauth2.StaticTokenSource(wifToken)

    // Create an impersonated token source
    impersonateSource, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
        TargetPrincipal: source.TargetPrincipal,
        Scopes:          source.scopes,
        Subject:         source.Subject,
        Delegates:       source.Delegates,
    }, option.WithTokenSource(tokenSource))
    if err != nil {
        return nil, fmt.Errorf("failed to create impersonated token source: %v", err)
    }

    // Get the token
    return impersonateSource.Token()
}
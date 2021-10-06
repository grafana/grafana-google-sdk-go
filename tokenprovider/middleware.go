package tokenprovider

import (
	"fmt"
	"net/http"

	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
)

const authenticationMiddlewareName = "GoogleAuthentication"

// AuthMiddleware creates the middleware for this token provider and scope
func AuthMiddleware(tokenProvider GoogleTokenProvider, scopes []string) httpclient.Middleware {
	return httpclient.NamedMiddlewareFunc(authenticationMiddlewareName, func(opts httpclient.Options, next http.RoundTripper) http.RoundTripper {
		return ApplyAuth(tokenProvider, scopes, next)
	})
}

// ApplyAuth adds the auth headers for the given token provider and scope
func ApplyAuth(tokenProvider GoogleTokenProvider, scopes []string, next http.RoundTripper) http.RoundTripper {
	return httpclient.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		token, err := tokenProvider.GetAccessToken(req.Context(), scopes)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve Google access token: %w", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		return next.RoundTrip(req)
	})
}

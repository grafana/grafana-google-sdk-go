package tokenprovider

import (
	"fmt"
	"net/http"

	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
)

const authenticationMiddlewareName = "GoogleAuthentication"

func AuthMiddleware(tokenProvider TokenProvider) httpclient.Middleware {
	return httpclient.NamedMiddlewareFunc(authenticationMiddlewareName, func(opts httpclient.Options, next http.RoundTripper) http.RoundTripper {
		return httpclient.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			token, err := tokenProvider.GetAccessToken(req.Context())
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve google access token: %w", err)
			}
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			return next.RoundTrip(req)
		})
	})
}

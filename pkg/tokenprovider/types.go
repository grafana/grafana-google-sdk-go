package tokenprovider

import "time"

// Config is the configuration for getting a TokenProvider.
type Config struct {
	RoutePath         string
	RouteMethod       string
	DataSourceID      int64
	DataSourceUpdated time.Time
	Scopes            []string

	// TargetPrincipal is only used when using service account impersonation
	TargetPrincipal string
	// JwtTokenConfig is only used for JWT tokens
	JwtTokenConfig *JwtTokenConfig
}

// JwtTokenConfig is the configuration for using JWT to fetch tokens.
type JwtTokenConfig struct {
	Email      string
	PrivateKey []byte
	URI        string
}

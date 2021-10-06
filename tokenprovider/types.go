package tokenprovider

import (
	"encoding/json"
)

type RoleType string

const (
	ROLE_VIEWER RoleType = "Viewer"
	ROLE_EDITOR RoleType = "Editor"
	ROLE_ADMIN  RoleType = "Admin"
)

type TokenProviderConfig struct {
	RoutePath         string
	RouteMethod       string
	DataSourceID      int64
	DataSourceVersion int
	JwtTokenConfig    *JwtTokenConfig
}

type JwtTokenConfig struct {
	Email      string
	PrivateKey []byte
	URI        string
}

// AppPluginRoute describes a plugin route that is defined in
// the plugin.json file for a plugin.
type AppPluginRoute struct {
	Path         string                   `json:"path"`
	Method       string                   `json:"method"`
	ReqRole      RoleType                 `json:"reqRole"`
	URL          string                   `json:"url"`
	URLParams    []AppPluginRouteURLParam `json:"urlParams"`
	Headers      []AppPluginRouteHeader   `json:"headers"`
	AuthType     string                   `json:"authType"`
	TokenAuth    *JwtTokenAuth            `json:"tokenAuth"`
	JwtTokenAuth *JwtTokenAuth            `json:"jwtTokenAuth"`
	Body         json.RawMessage          `json:"body"`
}

// AppPluginRouteHeader describes an HTTP header that is forwarded with
// the proxied request for a plugin route
type AppPluginRouteHeader struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// AppPluginRouteURLParam describes query string parameters for
// a url in a plugin route
type AppPluginRouteURLParam struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// JwtTokenAuth struct for JWT Token Auth with an uploaded JWT file
type JwtTokenAuth struct {
	Url    string            `json:"url"`
	Scopes []string          `json:"scopes"`
	Params map[string]string `json:"params"`
}

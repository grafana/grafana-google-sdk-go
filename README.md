# Grafana Google SDK for Go

A Go SDK for integrating Grafana with Google Cloud Platform services, providing authentication and token management for Google Cloud APIs.

## Features

- Multiple authentication methods:
  - Workload Identity Federation (WIF) with JWT bearer tokens
  - Service account impersonation
  - JWT-based authentication
  - GCE instance metadata
- Token caching and automatic refresh
- Support for custom token URLs and scopes
- Comprehensive test coverage

## Installation

```bash
go get github.com/grafana/grafana-google-sdk-go/pkg/tokenprovider
```

## Authentication Methods

### Workload Identity Federation (WIF)

Workload Identity Federation allows workloads from external identity providers to access Google Cloud resources without using a service account key.

#### Configuration

```go
import "github.com/grafana/grafana-google-sdk-go/pkg/tokenprovider"

config := tokenprovider.Config{
    Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
}

wifConfig := &tokenprovider.WifConfig{
    Audience:        "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
    TokenURL:        "https://sts.googleapis.com/v1/token", // Optional, defaults to Google's STS endpoint
    SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    JwtBearerToken:   "YOUR_JWT_TOKEN",
}

provider, err := tokenprovider.NewWifAccessTokenProvider(config, wifConfig)
if err != nil {
    // Handle error
}

token, err := provider.GetAccessToken(context.Background())
// Use token...
```

#### Impersonation with WIF

```go
config := tokenprovider.Config{
    TargetPrincipal: "target-service-account@project.iam.gserviceaccount.com",
    Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
}

wifConfig := &tokenprovider.WifConfig{
    Audience:        "//iam.googleapis.com/...",
    SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    JwtBearerToken:   "YOUR_JWT_TOKEN",
    // Optional: You can also specify ServiceAccountEmail instead of TargetPrincipal in Config
    // ServiceAccountEmail: "target-service-account@project.iam.gserviceaccount.com",
}

provider, err := tokenprovider.NewImpersonatedWifAccessTokenProvider(config, wifConfig)
// Use provider...
```

### JWT Authentication

```go
config := tokenprovider.Config{
    Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
    JwtTokenConfig: tokenprovider.JwtTokenConfig{
        Email:      "service-account-email@project.iam.gserviceaccount.com",
        PrivateKey: []byte("-----BEGIN PRIVATE KEY-----\n..."),
        URI:        "https://oauth2.googleapis.com/token",
    },
}

provider := tokenprovider.NewJwtAccessTokenProvider(config)
```

### GCE Instance Metadata

```go
provider := tokenprovider.NewGceAccessTokenProvider(tokenprovider.Config{
    Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
})
```

## Error Handling

All token provider functions return errors that implement the standard `error` interface. Common error cases include:

- Missing or invalid configuration
- Network errors during token exchange
- Authentication failures
- Token validation errors

## Testing

Run the tests with:

```bash
go test ./... -v
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for more information.

## Contributing

If you're interested in contributing to this project:

- Start by reading the [Contributing guide](/CONTRIBUTING.md).
- Learn how to set up your local environment, in our [Developer guide](/contribute/developer-guide.md).

## License

[Apache 2.0 License](https://github.com/grafana/grafana-google-sdk-go/blob/master/LICENSE)

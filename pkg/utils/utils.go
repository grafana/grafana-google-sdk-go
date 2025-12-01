package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"golang.org/x/oauth2/google"
)

func GCEDefaultProject(ctx context.Context, scope string) (string, error) {
	defaultCredentials, err := google.FindDefaultCredentials(ctx, scope)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve default project from GCE metadata server: %w", err)
	}
	token, err := defaultCredentials.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve GCP credential token: %w", err)
	}
	if !token.Valid() {
		return "", errors.New("failed to validate GCP credentials")
	}

	return defaultCredentials.ProjectID, nil
}

func readPrivateKeyFromFile(rsaPrivateKeyLocation string) (string, error) {
	if rsaPrivateKeyLocation == "" {
		return "", fmt.Errorf("missing file location for private key")
	}

	data, err := os.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return "", fmt.Errorf("could not read private key file from file system: %w", err)
	}

	// If file seems to be a service account JSON, try extracting private_key
	if strings.HasSuffix(strings.ToLower(rsaPrivateKeyLocation), ".json") {
		var sa struct {
			PrivateKey string `json:"private_key"`
		}

		if err := json.Unmarshal(data, &sa); err != nil {
			return "", fmt.Errorf("failed to parse service account JSON: %w", err)
		}
		if sa.PrivateKey == "" {
			return "", fmt.Errorf("service account JSON does not contain private_key")
		}

		return strings.ReplaceAll(sa.PrivateKey, "\\n", "\n"), nil
	}

	// Otherwise assume it's a raw PEM key
	return string(data), nil
}

type JSONData struct {
	PrivateKeyPath string `json:"privateKeyPath"`
}

// Check if a private key path was provided. Fall back to the plugin's default method
// of an inline private key
func GetPrivateKey(settings *backend.DataSourceInstanceSettings) (string, error) {
	jsonData := JSONData{}

	if err := json.Unmarshal(settings.JSONData, &jsonData); err != nil {
		return "", fmt.Errorf("could not unmarshal DataSourceInfo json: %w", err)
	}

	if jsonData.PrivateKeyPath != "" {
		privateKey, err := readPrivateKeyFromFile(jsonData.PrivateKeyPath)
		if err != nil {
			return "", fmt.Errorf("could not read private key from file: %w", err)
		}
		return privateKey, nil
	}

	privateKey := settings.DecryptedSecureJSONData["privateKey"]

	// React might escape newline characters like this \\n so we need to handle that
	return strings.ReplaceAll(privateKey, "\\n", "\n"), nil
}

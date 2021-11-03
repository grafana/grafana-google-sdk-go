package utils

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2/google"
)

func GCEDefaultProject(ctx context.Context) (string, error) {
	defaultCredentials, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/monitoring.read")
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

package utils

import (
	"context"
	"errors"
	"fmt"

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

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadPrivateKeyFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("should read raw PEM file", func(t *testing.T) {
		pemContent := "-----BEGIN PRIVATE KEY-----\nABC123\n-----END PRIVATE KEY-----"
		pemPath := filepath.Join(tmpDir, "key.pem")
		require.NoError(t, os.WriteFile(pemPath, []byte(pemContent), 0o600))

		key, err := readPrivateKeyFromFile(pemPath)
		require.NoError(t, err)
		require.Equal(t, pemContent, key)
	})

	t.Run("should read private_key from JSON service account", func(t *testing.T) {
		expectedKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDauVDiksqPFoUv
nP6BHrgMyTRam3eySV+UtVL3Am/4I3n1n28s1/ErPicm8mHfgvFamuFAQgjGero7
...
-----END PRIVATE KEY-----
`

		jsonContent := fmt.Sprintf(`{
  "type": "service_account",
  "project_id": "project-12345",
  "private_key_id": "b12340d6e22123492e50aa7ee7fde6a8e",
  "private_key": %q,
  "client_email": "project-12345-gr-1762312345@project-12345.iam.gserviceaccount.com",
  "client_id": "103374474865745151503",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/project-12345-gr-1762312345%%40project-12345.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}`, expectedKey)

		jsonPath := filepath.Join(tmpDir, "service-account.json")
		require.NoError(t, os.WriteFile(jsonPath, []byte(jsonContent), 0o600))

		key, err := readPrivateKeyFromFile(jsonPath)
		require.NoError(t, err)
		require.Equal(t, expectedKey, key)
	})

	t.Run("should fail with missing file", func(t *testing.T) {
		_, err := readPrivateKeyFromFile(filepath.Join(tmpDir, "does_not_exist.pem"))
		require.Error(t, err)
	})
}

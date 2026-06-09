package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectErr     bool
		expectedError string
	}{
		{
			name:        "valid API key",
			authHeader:  "ApiKey my-secret-key",
			expectedKey: "my-secret-key",
			expectErr:   false,
		},
		{
			name:          "missing authorization header",
			authHeader:    "",
			expectErr:     true,
			expectedError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:          "wrong auth scheme",
			authHeader:    "Bearer my-secret-key",
			expectErr:     true,
			expectedError: "malformed authorization header",
		},
		{
			name:          "missing API key value",
			authHeader:    "ApiKey",
			expectErr:     true,
			expectedError: "malformed authorization header",
		},
		{
			name:          "empty scheme with key",
			authHeader:    " my-secret-key",
			expectErr:     true,
			expectedError: "malformed authorization header",
		},
		{
			name:        "multiple spaces after scheme",
			authHeader:  "ApiKey  my-secret-key",
			expectedKey: "",
			expectErr:   false, // current implementation returns splitAuth[1] == ""
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.expectedError {
					t.Fatalf("expected error %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Fatalf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}

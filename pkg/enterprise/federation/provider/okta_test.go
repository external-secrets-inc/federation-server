// /*
// Copyright © 2025 ESO Maintainer Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

// Package provider implements the federation provider.
// Copyright External Secrets Inc.
// All Rights Reserved.
package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOktaProvider(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		authServerID       string
		expectedAuthServer string
	}{
		{
			name:               "with custom auth server",
			domain:             "https://dev-12345.okta.com",
			authServerID:       "custom",
			expectedAuthServer: "custom",
		},
		{
			name:               "with empty auth server defaults to default",
			domain:             "https://dev-12345.okta.com",
			authServerID:       "",
			expectedAuthServer: "default",
		},
		{
			name:               "with default auth server",
			domain:             "https://dev-12345.okta.com",
			authServerID:       "default",
			expectedAuthServer: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewOktaProvider(tt.domain, tt.authServerID)

			assert.Equal(t, tt.domain, provider.Domain)
			assert.Equal(t, tt.expectedAuthServer, provider.AuthorizationServerID)
			assert.NotNil(t, provider.httpClient)
			assert.NotNil(t, provider.jwksCache)
			assert.Equal(t, defaultJWKSCacheTTL, provider.cacheTTL)
		})
	}
}

func TestOktaProvider_GetJWKS(t *testing.T) {
	tests := []struct {
		name           string
		authServerID   string
		mockResponse   interface{}
		mockStatusCode int
		expectError    bool
		errorContains  string
		expectedKeys   int
	}{
		{
			name:           "successful JWKS fetch",
			authServerID:   "default",
			mockStatusCode: http.StatusOK,
			mockResponse: map[string]interface{}{
				"keys": []map[string]string{
					{
						"kid": "key1",
						"kty": "RSA",
						"n":   "test-modulus",
						"e":   "AQAB",
					},
					{
						"kid": "key2",
						"kty": "RSA",
						"n":   "test-modulus-2",
						"e":   "AQAB",
					},
				},
			},
			expectedKeys: 2,
		},
		{
			name:           "empty JWKS response",
			authServerID:   "default",
			mockStatusCode: http.StatusOK,
			mockResponse: map[string]interface{}{
				"keys": []map[string]string{},
			},
			expectError:   true,
			errorContains: "no valid keys found",
		},
		{
			name:           "JWKS keys without kid",
			authServerID:   "default",
			mockStatusCode: http.StatusOK,
			mockResponse: map[string]interface{}{
				"keys": []map[string]string{
					{
						"kty": "RSA",
						"n":   "test-modulus",
						"e":   "AQAB",
					},
				},
			},
			expectError:   true,
			errorContains: "no valid keys found",
		},
		{
			name:           "HTTP error status",
			authServerID:   "default",
			mockStatusCode: http.StatusUnauthorized,
			mockResponse:   map[string]string{"error": "unauthorized"},
			expectError:    true,
			errorContains:  "status 401",
		},
		{
			name:           "invalid JSON response",
			authServerID:   "default",
			mockStatusCode: http.StatusOK,
			mockResponse:   "invalid json",
			expectError:    true,
			errorContains:  "failed to parse JWKS response",
		},
		{
			name:           "successful JWKS fetch with custom auth server",
			authServerID:   "custom",
			mockStatusCode: http.StatusOK,
			mockResponse: map[string]interface{}{
				"keys": []map[string]string{
					{
						"kid": "key1",
						"kty": "RSA",
						"n":   "test-modulus",
						"e":   "AQAB",
					},
				},
			},
			expectedKeys: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// For "default" auth server, Okta uses org authorization server endpoint without auth server ID
				expectedPath := "/oauth2/v1/keys"
				if tt.authServerID != "" && tt.authServerID != "default" {
					expectedPath = "/oauth2/" + tt.authServerID + "/v1/keys"
				}
				assert.Contains(t, r.URL.Path, expectedPath)

				w.WriteHeader(tt.mockStatusCode)

				if str, ok := tt.mockResponse.(string); ok {
					_, _ = w.Write([]byte(str))
				} else {
					_ = json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			provider := NewOktaProvider(server.URL, tt.authServerID)
			ctx := context.Background()

			jwks, err := provider.GetJWKS(ctx, "", "", nil)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, jwks, tt.expectedKeys)
			}
		})
	}
}

func TestOktaProvider_GetJWKS_Caching(t *testing.T) {
	requestCount := 0

	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{
					"kid": "key1",
					"kty": "RSA",
					"n":   "test-modulus",
					"e":   "AQAB",
				},
			},
		})
	}))
	defer server.Close()

	provider := NewOktaProvider(server.URL, "default")
	provider.cacheTTL = 100 * time.Millisecond // Short TTL for testing

	ctx := context.Background()

	// First request - should hit the server
	jwks1, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks1, 1)
	assert.Equal(t, 1, requestCount)

	// Second request - should use cache
	jwks2, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks2, 1)
	assert.Equal(t, 1, requestCount, "should not make another request due to cache")

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third request - should hit the server again after cache expiry
	jwks3, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks3, 1)
	assert.Equal(t, 2, requestCount, "should make another request after cache expiry")
}

func TestOktaProvider_GetJWKS_ContextCancellation(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{},
		})
	}))
	defer server.Close()

	provider := NewOktaProvider(server.URL, "default")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := provider.GetJWKS(ctx, "", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "test-client-id"
	testClientSecret = "test-client-secret"
)

func TestNewPingIdentityProvider(t *testing.T) {
	tests := []struct {
		name          string
		region        string
		environmentID string
	}{
		{
			name:          "with region com",
			region:        "com",
			environmentID: "12345678-1234-1234-1234-123456789abc",
		},
		{
			name:          "with region eu",
			region:        "eu",
			environmentID: "87654321-4321-4321-4321-cba987654321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewPingIdentityProvider(tt.region, tt.environmentID)

			assert.Equal(t, tt.region, provider.Region)
			assert.Equal(t, tt.environmentID, provider.EnvironmentID)
			assert.NotNil(t, provider.httpClient)
			assert.NotNil(t, provider.jwksCache)
			assert.Equal(t, defaultPingIdentityJWKSCacheTTL, provider.cacheTTL)
		})
	}
}

func TestPingIdentityProvider_GetJWKS(t *testing.T) {
	tests := []struct {
		name                  string
		mockDiscoveryResponse interface{}
		mockDiscoveryStatus   int
		mockJWKSResponse      interface{}
		mockJWKSStatus        int
		expectError           bool
		errorContains         string
		expectedKeys          int
	}{
		{
			name:                "successful JWKS fetch",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"jwks_uri": "JWKS_URL_PLACEHOLDER",
			},
			mockJWKSStatus: http.StatusOK,
			mockJWKSResponse: map[string]interface{}{
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
			name:                "empty JWKS response",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"jwks_uri": "JWKS_URL_PLACEHOLDER",
			},
			mockJWKSStatus: http.StatusOK,
			mockJWKSResponse: map[string]interface{}{
				"keys": []map[string]string{},
			},
			expectError:   true,
			errorContains: "no valid keys found",
		},
		{
			name:                "JWKS keys without kid",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"jwks_uri": "JWKS_URL_PLACEHOLDER",
			},
			mockJWKSStatus: http.StatusOK,
			mockJWKSResponse: map[string]interface{}{
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
			name:                "HTTP error status from JWKS",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"jwks_uri": "JWKS_URL_PLACEHOLDER",
			},
			mockJWKSStatus:   http.StatusUnauthorized,
			mockJWKSResponse: map[string]string{"error": "unauthorized"},
			expectError:      true,
			errorContains:    "status 401",
		},
		{
			name:                "invalid JSON in JWKS response",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"jwks_uri": "JWKS_URL_PLACEHOLDER",
			},
			mockJWKSStatus:   http.StatusOK,
			mockJWKSResponse: "invalid json",
			expectError:      true,
			errorContains:    "failed to parse JWKS response",
		},
		{
			name:                "discovery endpoint error",
			mockDiscoveryStatus: http.StatusNotFound,
			mockDiscoveryResponse: map[string]string{
				"error": "not found",
			},
			expectError:   true,
			errorContains: "discovery endpoint returned status 404",
		},
		{
			name:                "discovery missing jwks_uri",
			mockDiscoveryStatus: http.StatusOK,
			mockDiscoveryResponse: map[string]interface{}{
				"issuer": "https://auth.pingone.com/env-id",
			},
			expectError:   true,
			errorContains: "discovery document missing jwks_uri field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock servers
			var jwksURL string
			jwksServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockJWKSStatus)
				if str, ok := tt.mockJWKSResponse.(string); ok {
					_, _ = w.Write([]byte(str))
				} else {
					_ = json.NewEncoder(w).Encode(tt.mockJWKSResponse)
				}
			}))
			defer jwksServer.Close()
			jwksURL = jwksServer.URL

			discoveryServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify discovery path
				assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)

				w.WriteHeader(tt.mockDiscoveryStatus)

				// Replace placeholder with actual JWKS URL
				switch response := tt.mockDiscoveryResponse.(type) {
				case map[string]interface{}:
					if response["jwks_uri"] == "JWKS_URL_PLACEHOLDER" {
						response["jwks_uri"] = jwksURL
					}
					_ = json.NewEncoder(w).Encode(response)
				case string:
					_, _ = w.Write([]byte(response))
				default:
					_ = json.NewEncoder(w).Encode(tt.mockDiscoveryResponse)
				}
			}))
			defer discoveryServer.Close()

			// Create provider and override the discovery URL for testing
			provider := NewPingIdentityProvider("com", "test-env-id")
			provider.discoveryBaseURL = discoveryServer.URL

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

func TestPingIdentityProvider_GetJWKS_Caching(t *testing.T) {
	discoveryRequestCount := 0
	jwksRequestCount := 0

	jwksServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequestCount++
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
	defer jwksServer.Close()

	discoveryServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryRequestCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jwks_uri": jwksServer.URL,
		})
	}))
	defer discoveryServer.Close()

	provider := NewPingIdentityProvider("com", "test-env")
	provider.discoveryBaseURL = discoveryServer.URL
	provider.cacheTTL = 100 * time.Millisecond // Short TTL for testing

	ctx := context.Background()

	// First request - should hit both discovery and JWKS
	jwks1, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks1, 1)
	assert.Equal(t, 1, discoveryRequestCount)
	assert.Equal(t, 1, jwksRequestCount)

	// Second request - should use cache
	jwks2, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks2, 1)
	assert.Equal(t, 1, discoveryRequestCount, "should not make another discovery request due to cache")
	assert.Equal(t, 1, jwksRequestCount, "should not make another JWKS request due to cache")

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third request - should hit JWKS again (but not discovery, as jwksURL is cached)
	jwks3, err := provider.GetJWKS(ctx, "", "", nil)
	require.NoError(t, err)
	assert.Len(t, jwks3, 1)
	assert.Equal(t, 1, discoveryRequestCount, "should not make another discovery request as jwksURL is cached")
	assert.Equal(t, 2, jwksRequestCount, "should make another JWKS request after cache expiry")
}

func TestPingIdentityProvider_GetJWKS_ContextCancellation(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jwks_uri": "http://example.com/jwks",
		})
	}))
	defer server.Close()

	provider := NewPingIdentityProvider("com", "test-env")
	provider.discoveryBaseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := provider.GetJWKS(ctx, "", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestPingIdentityProvider_CheckIdentityExists(t *testing.T) {
	t.Run("no management API configured - assumes exists", func(t *testing.T) {
		provider := NewPingIdentityProvider("com", "test-env-id")
		ctx := context.Background()

		// Should return true when no management API credentials are configured
		exists, err := provider.CheckIdentityExists(ctx, "some-client-id")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("app exists and is enabled", func(t *testing.T) {
		// Mock token server
		tokenServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		// Mock management API server
		managementServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/environments/test-env-id/applications/test-app-id", r.URL.Path)
			assert.Equal(t, "Bearer mock-access-token", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "test-app-id",
				"enabled": true,
			})
		}))
		defer managementServer.Close()

		provider := NewPingIdentityProvider("com", "test-env-id")
		provider.ManagementClientID = testClientID
		provider.ManagementClientSecret = testClientSecret

		// Override URLs for testing
		provider.httpClient = &http.Client{
			Transport: &mockRoundTripper{
				tokenURL:         fmt.Sprintf("https://auth.pingone.com/test-env-id/as/token"),
				tokenServer:      tokenServer.URL,
				managementURL:    fmt.Sprintf("https://api.pingone.com/v1/environments/test-env-id/applications/test-app-id"),
				managementServer: managementServer.URL + "/v1/environments/test-env-id/applications/test-app-id",
			},
		}

		ctx := context.Background()
		exists, err := provider.CheckIdentityExists(ctx, "test-app-id")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("app exists but is disabled", func(t *testing.T) {
		tokenServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		managementServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "test-app-id",
				"enabled": false, // Disabled
			})
		}))
		defer managementServer.Close()

		provider := NewPingIdentityProvider("com", "test-env-id")
		provider.ManagementClientID = testClientID
		provider.ManagementClientSecret = testClientSecret

		provider.httpClient = &http.Client{
			Transport: &mockRoundTripper{
				tokenURL:         fmt.Sprintf("https://auth.pingone.com/test-env-id/as/token"),
				tokenServer:      tokenServer.URL,
				managementURL:    fmt.Sprintf("https://api.pingone.com/v1/environments/test-env-id/applications/test-app-id"),
				managementServer: managementServer.URL + "/v1/environments/test-env-id/applications/test-app-id",
			},
		}

		ctx := context.Background()
		exists, err := provider.CheckIdentityExists(ctx, "test-app-id")
		require.NoError(t, err)
		assert.False(t, exists) // Should return false for disabled apps
	})

	t.Run("app not found", func(t *testing.T) {
		tokenServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		managementServer := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    "NOT_FOUND",
				"message": "Application not found",
			})
		}))
		defer managementServer.Close()

		provider := NewPingIdentityProvider("com", "test-env-id")
		provider.ManagementClientID = testClientID
		provider.ManagementClientSecret = testClientSecret

		provider.httpClient = &http.Client{
			Transport: &mockRoundTripper{
				tokenURL:         fmt.Sprintf("https://auth.pingone.com/test-env-id/as/token"),
				tokenServer:      tokenServer.URL,
				managementURL:    fmt.Sprintf("https://api.pingone.com/v1/environments/test-env-id/applications/test-app-id"),
				managementServer: managementServer.URL + "/v1/environments/test-env-id/applications/test-app-id",
			},
		}

		ctx := context.Background()
		exists, err := provider.CheckIdentityExists(ctx, "test-app-id")
		require.NoError(t, err)
		assert.False(t, exists) // Should return false for not found
	})
}

// mockRoundTripper helps mock HTTP requests for testing.
type mockRoundTripper struct {
	tokenURL         string
	tokenServer      string
	managementURL    string
	managementServer string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Route token requests to token server
	if strings.Contains(req.URL.String(), "/as/token") {
		req.URL, _ = url.Parse(m.tokenServer)
		return http.DefaultTransport.RoundTrip(req)
	}
	// Route management API requests to management server
	if strings.Contains(req.URL.String(), "/applications/") {
		req.URL, _ = url.Parse(m.managementServer)
		return http.DefaultTransport.RoundTrip(req)
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

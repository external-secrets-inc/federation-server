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
	"strings"
	"sync"
	"time"
)

const (
	// Default cache TTL for JWKS (1 hour).
	defaultPingIdentityJWKSCacheTTL = 1 * time.Hour
)

// PingIdentityProvider implements the PingIdentity provider.
type PingIdentityProvider struct {
	Region                 string
	EnvironmentID          string
	ManagementClientID     string // Optional: Worker app client ID for Management API
	ManagementClientSecret string // Optional: Worker app client secret for Management API
	httpClient             *http.Client
	jwksCache              map[string]map[string]string
	cacheMutex             sync.RWMutex
	lastFetch              time.Time
	cacheTTL               time.Duration
	jwksURL                string // Cached JWKS URL from discovery
	// discoveryBaseURL is used for testing to override the discovery endpoint
	// If empty, uses the standard PingOne URL format
	discoveryBaseURL string
	// managementAccessToken is cached for Management API calls
	managementAccessToken string
	managementTokenExpiry time.Time
	managementTokenMutex  sync.RWMutex
}

// NewPingIdentityProvider creates a new PingIdentity provider.
func NewPingIdentityProvider(region, environmentID string) *PingIdentityProvider {
	return &PingIdentityProvider{
		Region:        region,
		EnvironmentID: environmentID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		jwksCache: make(map[string]map[string]string),
		cacheTTL:  defaultPingIdentityJWKSCacheTTL,
	}
}

// GetJWKS fetches the JSON Web Key Set from PingOne's public endpoint.
// The token, issuer, and caCrt parameters are not used for PingOne since the
// JWKS endpoint is publicly accessible over standard HTTPS.
func (p *PingIdentityProvider) GetJWKS(ctx context.Context, _, _ string, _ []byte) (map[string]map[string]string, error) {
	p.cacheMutex.RLock()
	// Check if cache is still valid
	if time.Since(p.lastFetch) < p.cacheTTL && len(p.jwksCache) > 0 {
		cachedJWKS := p.jwksCache
		p.cacheMutex.RUnlock()
		return cachedJWKS, nil
	}
	p.cacheMutex.RUnlock()

	// Fetch fresh JWKS
	return p.fetchAndCacheJWKS(ctx)
}

func (p *PingIdentityProvider) fetchAndCacheJWKS(ctx context.Context) (map[string]map[string]string, error) {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if time.Since(p.lastFetch) < p.cacheTTL && len(p.jwksCache) > 0 {
		return p.jwksCache, nil
	}

	// If we don't have the JWKS URL yet, fetch it from discovery
	if p.jwksURL == "" {
		if err := p.fetchJWKSURLFromDiscovery(ctx); err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS URL from discovery: %w", err)
		}
	}

	// Fetch JWKS from the discovered URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from PingOne: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwksResponse struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwksResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS response: %w (body: %s)", err, string(body))
	}

	// Convert to map[kid]key format, converting values to strings
	jwksMap := make(map[string]map[string]string)
	for _, key := range jwksResponse.Keys {
		kidInterface, ok := key["kid"]
		if !ok {
			continue
		}
		kid, ok := kidInterface.(string)
		if !ok {
			continue
		}

		// Convert interface{} values to strings (skip arrays like x5c)
		stringKey := make(map[string]string)
		for k, v := range key {
			if strVal, ok := v.(string); ok {
				stringKey[k] = strVal
			}
			// Skip arrays and other non-string types
		}
		jwksMap[kid] = stringKey
	}

	if len(jwksMap) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS response")
	}

	// Update cache
	p.jwksCache = jwksMap
	p.lastFetch = time.Now()

	return jwksMap, nil
}

// fetchJWKSURLFromDiscovery fetches the JWKS URI from PingOne's OIDC discovery endpoint.
func (p *PingIdentityProvider) fetchJWKSURLFromDiscovery(ctx context.Context) error {
	// Construct discovery URL: https://auth.pingone.{region}/{envID}/as/.well-known/openid-configuration
	var discoveryURL string
	if p.discoveryBaseURL != "" {
		// Use override for testing
		discoveryURL = p.discoveryBaseURL + "/.well-known/openid-configuration"
	} else {
		// Use standard PingOne URL format (note the /as path component)
		discoveryURL = fmt.Sprintf("https://auth.pingone.%s/%s/as/.well-known/openid-configuration", p.Region, p.EnvironmentID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discovery endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read discovery response: %w", err)
	}

	var discoveryDoc struct {
		JwksURI string `json:"jwks_uri"`
	}

	if err := json.Unmarshal(body, &discoveryDoc); err != nil {
		return fmt.Errorf("failed to parse discovery document: %w", err)
	}

	if discoveryDoc.JwksURI == "" {
		return fmt.Errorf("discovery document missing jwks_uri field")
	}

	p.jwksURL = discoveryDoc.JwksURI
	return nil
}

// CheckIdentityExists checks if a PingOne application still exists and is enabled by calling the PingOne Management API.
// The subject parameter should be the PingOne application client ID.
// Returns true if the app exists and is enabled, false if deleted/not found/disabled.
// If Management API credentials are not configured, returns true (assume exists).
func (p *PingIdentityProvider) CheckIdentityExists(ctx context.Context, subject string) (bool, error) {
	// If no management API credentials configured, skip the check (assume exists)
	if p.ManagementClientID == "" || p.ManagementClientSecret == "" {
		return true, nil
	}

	// Get management API access token (with caching)
	accessToken, err := p.getManagementAccessToken(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get management API access token: %w", err)
	}

	// Call PingOne Management API: GET /v1/environments/{envId}/applications/{appId}
	url := fmt.Sprintf("https://api.pingone.%s/v1/environments/%s/applications/%s", p.Region, p.EnvironmentID, subject)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// PingOne Management API uses Bearer token authentication
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call PingOne Management API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// App exists - now check if it's enabled
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %w", err)
		}

		var appResponse struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(body, &appResponse); err != nil {
			return false, fmt.Errorf("failed to parse app response: %w", err)
		}

		// Only consider enabled apps as existing
		// Disabled apps should trigger cleanup
		if !appResponse.Enabled {
			return false, nil
		}

		return true, nil

	case http.StatusNotFound:
		// App doesn't exist (deleted)
		return false, nil

	case http.StatusForbidden:
		// Forbidden - worker app may not have permission
		// Log this but don't fail - assume exists to avoid false positives
		return true, nil

	default:
		// Other errors - read body for details
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status %d from PingOne Management API: %s", resp.StatusCode, string(body))
	}
}

// getManagementAccessToken obtains an access token for PingOne Management API using client credentials.
// Tokens are cached and refreshed when expired.
func (p *PingIdentityProvider) getManagementAccessToken(ctx context.Context) (string, error) {
	p.managementTokenMutex.RLock()
	// Check if we have a valid cached token
	if p.managementAccessToken != "" && time.Now().Before(p.managementTokenExpiry) {
		token := p.managementAccessToken
		p.managementTokenMutex.RUnlock()
		return token, nil
	}
	p.managementTokenMutex.RUnlock()

	// Need to fetch a new token
	p.managementTokenMutex.Lock()
	defer p.managementTokenMutex.Unlock()

	// Double-check after acquiring write lock
	if p.managementAccessToken != "" && time.Now().Before(p.managementTokenExpiry) {
		return p.managementAccessToken, nil
	}

	// Fetch token from PingOne using Basic Authentication
	// Worker apps in PingOne use client_secret_basic authentication method
	tokenURL := fmt.Sprintf("https://auth.pingone.%s/%s/as/token", p.Region, p.EnvironmentID)

	// Use only grant_type in body, credentials go in Authorization header
	data := "grant_type=client_credentials"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	// Set Basic Authentication with client credentials
	req.SetBasicAuth(p.ManagementClientID, p.ManagementClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}

	// Cache the token (with 60 second buffer before expiry)
	p.managementAccessToken = tokenResponse.AccessToken
	p.managementTokenExpiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn-60) * time.Second)

	return tokenResponse.AccessToken, nil
}

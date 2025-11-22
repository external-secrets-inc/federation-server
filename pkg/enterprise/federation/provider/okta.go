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
	"sync"
	"time"
)

const (
	// Default cache TTL for JWKS (1 hour as recommended by Okta).
	defaultJWKSCacheTTL = 1 * time.Hour
	defaultServerID     = "default"
)

// OktaProvider implements the Okta provider.
type OktaProvider struct {
	Domain                string
	AuthorizationServerID string
	ManagementAPIToken    string // Optional: for calling Okta Management API
	httpClient            *http.Client
	jwksCache             map[string]map[string]string
	cacheMutex            sync.RWMutex
	lastFetch             time.Time
	cacheTTL              time.Duration
}

// NewOktaProvider creates a new Okta provider.
func NewOktaProvider(domain, authServerID string) *OktaProvider {
	if authServerID == "" {
		authServerID = defaultServerID
	}

	return &OktaProvider{
		Domain:                domain,
		AuthorizationServerID: authServerID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		jwksCache: make(map[string]map[string]string),
		cacheTTL:  defaultJWKSCacheTTL,
	}
}

// GetJWKS fetches the JSON Web Key Set from Okta's public endpoint.
// The token, issuer, and caCrt parameters are not used for Okta since the
// JWKS endpoint is publicly accessible over standard HTTPS.
func (o *OktaProvider) GetJWKS(ctx context.Context, _, _ string, _ []byte) (map[string]map[string]string, error) {
	o.cacheMutex.RLock()
	// Check if cache is still valid
	if time.Since(o.lastFetch) < o.cacheTTL && len(o.jwksCache) > 0 {
		cachedJWKS := o.jwksCache
		o.cacheMutex.RUnlock()
		return cachedJWKS, nil
	}
	o.cacheMutex.RUnlock()

	// Fetch fresh JWKS
	return o.fetchAndCacheJWKS(ctx)
}

func (o *OktaProvider) fetchAndCacheJWKS(ctx context.Context) (map[string]map[string]string, error) {
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if time.Since(o.lastFetch) < o.cacheTTL && len(o.jwksCache) > 0 {
		return o.jwksCache, nil
	}

	// Construct JWKS URL
	// Org authorization server: https://{domain}/oauth2/v1/keys
	// Custom authorization server: https://{domain}/oauth2/{authServerId}/v1/keys
	var jwksURL string
	if o.AuthorizationServerID == "" || o.AuthorizationServerID == defaultServerID {
		// Org authorization server (no auth server ID in path)
		jwksURL = fmt.Sprintf("%s/oauth2/v1/keys", o.Domain)
	} else {
		// Custom authorization server
		jwksURL = fmt.Sprintf("%s/oauth2/%s/v1/keys", o.Domain, o.AuthorizationServerID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from Okta: %w", err)
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
		Keys []map[string]string `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwksResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS response: %w", err)
	}

	// Convert to map[kid]key format
	jwksMap := make(map[string]map[string]string)
	for _, key := range jwksResponse.Keys {
		kid, ok := key["kid"]
		if !ok {
			continue
		}
		jwksMap[kid] = key
	}

	if len(jwksMap) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS response")
	}

	// Update cache
	o.jwksCache = jwksMap
	o.lastFetch = time.Now()

	return jwksMap, nil
}

// CheckIdentityExists checks if an Okta application still exists and is active by calling the Okta Management API.
// The subject parameter should be the Okta application client ID.
// Returns true if the app exists and is active, false if deleted/not found/inactive.
// If ManagementAPIToken is not configured, returns true (assume exists).
func (o *OktaProvider) CheckIdentityExists(ctx context.Context, subject string) (bool, error) {
	// If no management API token configured, skip the check (assume exists)
	if o.ManagementAPIToken == "" {
		return true, nil
	}

	// Call Okta Management API: GET /api/v1/apps/{clientId}
	url := fmt.Sprintf("%s/api/v1/apps/%s", o.Domain, subject)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Okta Management API uses SSWS authentication
	req.Header.Set("Authorization", "SSWS "+o.ManagementAPIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call Okta Management API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// App exists - now check if it's active
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %w", err)
		}

		var appResponse struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &appResponse); err != nil {
			return false, fmt.Errorf("failed to parse app response: %w", err)
		}

		// Only consider ACTIVE apps as existing
		// INACTIVE, DELETED, or any other status should trigger cleanup
		if appResponse.Status != "ACTIVE" {
			return false, nil
		}

		return true, nil
	case http.StatusNotFound:
		// App deleted or never existed
		return false, nil
	default:
		// Unexpected error - return error to avoid accidental deletion
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status %d from Okta Management API: %s", resp.StatusCode, string(body))
	}
}

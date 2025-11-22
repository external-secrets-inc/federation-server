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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KubernetesProvider defines a Kubernetes Identity Provider.
type KubernetesProvider struct {
	URL string
}

// NewProvider returns a Kubernetes Provider.
func NewProvider(url string) *KubernetesProvider {
	return &KubernetesProvider{
		URL: url,
	}
}

// CheckIdentityExists checks if a Kubernetes service account still exists.
// For Kubernetes federation, identity lifecycle is managed through WorkloadBinding,
// so this always returns true (identity check happens via pod/SA checks in AuthorizedIdentity controller).
func (k *KubernetesProvider) CheckIdentityExists(_ context.Context, _ string) (bool, error) {
	// Kubernetes federation uses WorkloadBinding for lifecycle management
	// This method is not used for K8s identities
	return true, nil
}

// GetJWKS fetches the JSON Web Key Set from Kubernetes's public endpoint.
func (k *KubernetesProvider) GetJWKS(ctx context.Context, token, _ string, caCrt []byte) (map[string]map[string]string, error) {
	// make url call to kubernetes endpoint using specified caCrt to validate tls
	// Parse
	b64dec, err := base64.StdEncoding.DecodeString(string(caCrt))
	if err != nil {
		return nil, err
	}
	// TODO[gusfcarvalho]: This only checks for one PEM block. we should support multiple
	block, _ := pem.Decode(b64dec)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid PEM block type")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	oidcConfigURL := fmt.Sprintf("%s/.well-known/openid-configuration", k.URL)
	sni := strings.TrimPrefix(k.URL, "https://")
	// TODO[gusfcarvalho]: factor out a method to generate http Clients
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: sni,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	// Get JWKS URL
	req, err := http.NewRequestWithContext(ctx, "GET", oidcConfigURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyMap := map[string]interface{}{}
	if err := json.Unmarshal(body, &bodyMap); err != nil {
		return nil, err
	}
	jwksURL, ok := bodyMap["jwks_uri"].(string)
	if !ok {
		return nil, fmt.Errorf("could not find jwks_uri in response")
	}
	parseURL, err := url.ParseRequestURI(jwksURL)
	if err != nil {
		return nil, err
	}
	realJwks := fmt.Sprintf("%s%s", k.URL, parseURL.Path)
	req, err = http.NewRequest("GET", realJwks, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err = httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	jwks := jwks{}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}
	jwksMap := map[string]map[string]string{}
	for _, key := range jwks.Keys {
		jwksMap[key["kid"]] = key
	}
	return jwksMap, nil
}

type jwks struct {
	Keys []map[string]string `json:"keys"`
}

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

// Package auth implements the federation server authorization.
// Copyright External Secrets Inc.
// All Rights Reserved.
package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
	"github.com/golang-jwt/jwt/v5"
)

// KubernetesIOInner represents the inner structure of the Kubernetes.io claim.
type KubernetesIOInner struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"serviceaccount"`
	Pod *struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"pod,omitempty"`
}

// KubernetesClaims represents the claims in an OIDC token.
type KubernetesClaims struct {
	jwt.RegisteredClaims
	KubernetesIOInner `json:"kubernetes.io"`
}

// OIDCAuthenticator defines authenticator structures for OIDC compatible ASs.
type OIDCAuthenticator struct {
	mu      sync.RWMutex
	specMap map[string][]*fedv1alpha1.AuthorizationSpec
}

// NewOIDCAuthenticator creates a new OIDCAuthenticator.
func NewOIDCAuthenticator() *OIDCAuthenticator {
	return &OIDCAuthenticator{
		mu:      sync.RWMutex{},
		specMap: map[string][]*fedv1alpha1.AuthorizationSpec{},
	}
}

// Authenticate implements Authenticator.
func (a *OIDCAuthenticator) Authenticate(r *http.Request) (*Info, error) {
	token := r.Header.Get("Authorization")
	onlyToken := strings.TrimPrefix(token, "Bearer ")
	caCert, err := readCaCrt(r)
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.ParseWithClaims(onlyToken, &KubernetesClaims{}, a.genParseToken(r.Context(), onlyToken, caCert))
	if err != nil {
		return nil, err
	}
	claim, ok := parsedToken.Claims.(*KubernetesClaims)
	if !ok {
		return nil, errors.New("failed to parse token")
	}
	authInfo := &Info{
		Method:   "oidc",
		Provider: claim.Issuer,
		Subject:  claim.Subject,
		KubeAttributes: &KubeAttributes{
			Namespace:      claim.Namespace,
			ServiceAccount: &ServiceAccount{Name: claim.ServiceAccount.Name, UID: claim.ServiceAccount.UID},
		},
	}
	if claim.Pod != nil {
		authInfo.KubeAttributes.Pod = &PodInfo{Name: claim.Pod.Name, UID: claim.Pod.UID}
	}
	return authInfo, nil
}

func parseRSAPublicKey(key map[string]string) (*rsa.PublicKey, error) {
	nval, ok := key["n"]
	if !ok {
		return nil, errors.New("n not found in key")
	}
	n, err := base64.RawURLEncoding.DecodeString(nval)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	eval, ok := key["e"]
	if !ok {
		return nil, errors.New("e not found in key")
	}
	e, err := base64.RawURLEncoding.DecodeString(eval)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	// Convert decoded values to big.Int
	modulus := new(big.Int).SetBytes(n)
	exponent := new(big.Int).SetBytes(e)
	// Create RSA public key
	return &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}, nil
}

func findJWKS(ctx context.Context, issuer, onlyToken, caCrt string) (map[*fedv1alpha1.AuthorizationSpec]map[string]map[string]string, error) {
	var specs map[*fedv1alpha1.AuthorizationSpec]map[string]map[string]string
	var errs error
	authorizationSpecs := store.Get(issuer)
	// Needs to be individual as at this stage we are filling the store
	for _, spec := range authorizationSpecs {
		jwks, err := store.GetJWKS(ctx, []*fedv1alpha1.AuthorizationSpec{spec}, onlyToken, issuer, []byte(caCrt))
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if jwks == nil {
			continue
		}
		if specs == nil {
			specs = map[*fedv1alpha1.AuthorizationSpec]map[string]map[string]string{}
		}
		specs[spec] = jwks
	}
	return specs, errs
}
func (a *OIDCAuthenticator) getJWKS(ctx context.Context, issuer, onlyToken, caCrt string) (map[string]map[string]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	specs, ok := a.specMap[caCrt]
	if !ok {
		specs, err := findJWKS(ctx, issuer, onlyToken, caCrt)
		if err != nil {
			return nil, err
		}
		for spec := range specs {
			a.specMap[caCrt] = append(a.specMap[caCrt], spec)
		}
	}
	return store.GetJWKS(ctx, specs, onlyToken, issuer, []byte(caCrt))
}

func (a *OIDCAuthenticator) genParseToken(ctx context.Context, onlyToken, caCrt string) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		var err error
		issuer, err := token.Claims.GetIssuer()
		if err != nil {
			return nil, err
		}
		jwks, err := a.getJWKS(ctx, issuer, onlyToken, caCrt)
		if err != nil {
			return nil, err
		}
		kid := token.Header["kid"].(string)
		key, ok := jwks[kid]
		if key == nil || !ok {
			return nil, errors.New("found right store, but kid not found in jwks")
		}
		alg := key["alg"]
		switch alg {
		case "RS256":
			return parseRSAPublicKey(key)
		case "RS384":
			return parseRSAPublicKey(key)
		case "RS512":
			return parseRSAPublicKey(key)
		default:
			return nil, fmt.Errorf("algorithm %v not supported", alg)
		}
	}
}
func readCaCrt(r *http.Request) (string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var tmp struct {
		CaCert string `json:"ca.crt"`
	}
	if err := json.Unmarshal(body, &tmp); err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	return tmp.CaCert, nil
}

func init() {
	Register("oidc", NewOIDCAuthenticator())
}

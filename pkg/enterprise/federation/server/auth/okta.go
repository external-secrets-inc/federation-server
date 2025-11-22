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
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// Default clock skew leeway (2 minutes as recommended by Okta).
	defaultClockSkewLeeway = 2 * time.Minute
)

// OktaClaims represents the claims in an Okta access token.
type OktaClaims struct {
	jwt.RegisteredClaims
	Version   int      `json:"ver,omitempty"`
	ClientID  string   `json:"cid,omitempty"`
	UserID    string   `json:"uid,omitempty"`
	Scopes    []string `json:"scp,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
}

// OktaAuthenticator implements Authenticator.
type OktaAuthenticator struct {
	mu              sync.RWMutex
	clockSkewLeeway time.Duration
}

// NewOktaAuthenticator creates a new OktaAuthenticator.
func NewOktaAuthenticator() *OktaAuthenticator {
	return &OktaAuthenticator{
		mu:              sync.RWMutex{},
		clockSkewLeeway: defaultClockSkewLeeway,
	}
}

// Authenticate implements Authenticator.
func (a *OktaAuthenticator) Authenticate(r *http.Request) (*Info, error) {
	// Extract Bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("invalid Authorization header format, expected 'Bearer <token>'")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, errors.New("empty token in Authorization header")
	}

	// Parse token without validation first to extract issuer
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &OktaClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*OktaClaims)
	if !ok {
		return nil, errors.New("invalid token claims format")
	}

	issuer, err := claims.GetIssuer()
	if err != nil || issuer == "" {
		return nil, errors.New("token missing issuer claim")
	}

	// Get JWKS from store
	authorizationSpecs := store.Get(issuer)
	if len(authorizationSpecs) == 0 {
		return nil, fmt.Errorf("no authorization configured for issuer: %s", issuer)
	}

	// Try to validate token with JWKS from store
	jwks, err := store.GetJWKS(r.Context(), authorizationSpecs, tokenString, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Parse and validate token with proper signature verification
	validatedToken, err := jwt.ParseWithClaims(tokenString, &OktaClaims{}, a.keyFunc(jwks))
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !validatedToken.Valid {
		return nil, errors.New("invalid token")
	}

	validatedClaims, ok := validatedToken.Claims.(*OktaClaims)
	if !ok {
		return nil, errors.New("invalid token claims after validation")
	}

	// Verify expiration with clock skew leeway
	if err := a.verifyExpiration(validatedClaims); err != nil {
		return nil, err
	}

	// Extract subject - for client credentials flow, sub equals cid
	subject, err := validatedClaims.GetSubject()
	if err != nil || subject == "" {
		return nil, errors.New("token missing subject claim")
	}

	// Build Info
	authInfo := &Info{
		Method:   "okta",
		Provider: issuer,
		Subject:  subject,
		// KubeAttributes will be nil for now - to be implemented in future
		KubeAttributes: nil,
	}

	return authInfo, nil
}

// keyFunc returns a function that looks up the signing key from JWKS.
func (a *OktaAuthenticator) keyFunc(jwks map[string]map[string]string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token missing 'kid' in header")
		}

		// Look up key in JWKS
		key, ok := jwks[kid]
		if !ok {
			return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
		}

		// Parse RSA public key from JWK
		return parseRSAPublicKeyFromJWK(key)
	}
}

// verifyExpiration checks token expiration with clock skew leeway.
func (a *OktaAuthenticator) verifyExpiration(claims *OktaClaims) error {
	if claims.ExpiresAt == nil {
		return errors.New("token missing expiration claim")
	}

	now := time.Now()
	expiresAt := claims.ExpiresAt.Time

	if now.After(expiresAt.Add(a.clockSkewLeeway)) {
		return fmt.Errorf("token expired at %s", expiresAt.Format(time.RFC3339))
	}

	return nil
}

// parseRSAPublicKeyFromJWK parses an RSA public key from a JWK map.
func parseRSAPublicKeyFromJWK(key map[string]string) (*rsa.PublicKey, error) {
	// Get modulus (n)
	nVal, ok := key["n"]
	if !ok {
		return nil, errors.New("JWK missing 'n' (modulus)")
	}

	n, err := base64.RawURLEncoding.DecodeString(nVal)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Get exponent (e)
	eVal, ok := key["e"]
	if !ok {
		return nil, errors.New("JWK missing 'e' (exponent)")
	}

	e, err := base64.RawURLEncoding.DecodeString(eVal)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert to big.Int
	modulus := new(big.Int).SetBytes(n)
	exponent := new(big.Int).SetBytes(e)

	// Verify key type
	kty, ok := key["kty"]
	if !ok || kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	return pubKey, nil
}

func init() {
	Register("okta", NewOktaAuthenticator())
}

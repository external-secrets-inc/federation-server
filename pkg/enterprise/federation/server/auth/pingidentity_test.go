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
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPingIdentityAuthenticator(t *testing.T) {
	auth := NewPingIdentityAuthenticator()

	assert.NotNil(t, auth)
	assert.Equal(t, defaultPingIdentityClockSkewLeeway, auth.clockSkewLeeway)
}

func TestPingIdentityAuthenticator_Authenticate_MissingAuthHeader(t *testing.T) {
	auth := NewPingIdentityAuthenticator()

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)

	_, err := auth.Authenticate(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing Authorization header")
}

func TestPingIdentityAuthenticator_Authenticate_InvalidAuthHeaderFormat(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
	}{
		{
			name:       "no Bearer prefix",
			authHeader: "InvalidToken",
		},
		{
			name:       "empty token",
			authHeader: "Bearer ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewPingIdentityAuthenticator()
			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			req.Header.Set("Authorization", tt.authHeader)

			_, err := auth.Authenticate(req)
			require.Error(t, err)
		})
	}
}

func createTestJWKSMapPingIdentity(pubKey *rsa.PublicKey, kid string) map[string]map[string]string {
	// Encode modulus (n)
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())

	// Encode exponent (e)
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return map[string]map[string]string{
		kid: {
			"kty": "RSA",
			"kid": kid,
			"n":   n,
			"e":   e,
			"alg": "RS256",
		},
	}
}

func TestParseRSAPublicKeyFromJWKPingIdentity(t *testing.T) {
	// Generate test key
	privateKey := generateTestRSAKey(t)
	publicKey := &privateKey.PublicKey

	// Create JWK
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]string{
		"kty": "RSA",
		"n":   n,
		"e":   e,
	}

	// Parse back
	parsedKey, err := parseRSAPublicKeyFromJWKPingIdentity(jwk)
	require.NoError(t, err)
	assert.Equal(t, publicKey.N, parsedKey.N)
	assert.Equal(t, publicKey.E, parsedKey.E)
}

func TestParseRSAPublicKeyFromJWKPingIdentity_Errors(t *testing.T) {
	tests := []struct {
		name          string
		jwk           map[string]string
		errorContains string
	}{
		{
			name:          "missing modulus",
			jwk:           map[string]string{"kty": "RSA", "e": "AQAB"},
			errorContains: "missing 'n'",
		},
		{
			name:          "missing exponent",
			jwk:           map[string]string{"kty": "RSA", "n": "test"},
			errorContains: "missing 'e'",
		},
		{
			name:          "invalid modulus encoding",
			jwk:           map[string]string{"kty": "RSA", "n": "invalid!!!", "e": "AQAB"},
			errorContains: "failed to decode modulus",
		},
		{
			name:          "invalid exponent encoding",
			jwk:           map[string]string{"kty": "RSA", "n": "dGVzdA", "e": "invalid!!!"},
			errorContains: "failed to decode exponent",
		},
		{
			name:          "unsupported key type",
			jwk:           map[string]string{"kty": "EC", "n": "dGVzdA", "e": "AQAB"},
			errorContains: "unsupported key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRSAPublicKeyFromJWKPingIdentity(tt.jwk)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestPingIdentityAuthenticator_VerifyExpiration(t *testing.T) {
	auth := NewPingIdentityAuthenticator()

	tests := []struct {
		name        string
		expiresAt   *jwt.NumericDate
		expectError bool
	}{
		{
			name:        "valid token - not expired",
			expiresAt:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			expectError: false,
		},
		{
			name:        "expired token - within leeway",
			expiresAt:   jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			expectError: false,
		},
		{
			name:        "expired token - outside leeway",
			expiresAt:   jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
			expectError: true,
		},
		{
			name:        "missing expiration",
			expiresAt:   nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &PingIdentityClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: tt.expiresAt,
				},
			}

			err := auth.verifyExpiration(claims)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPingIdentityAuthenticator_KeyFunc(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	kid := "test-kid"

	jwks := createTestJWKSMapPingIdentity(&privateKey.PublicKey, kid)

	auth := NewPingIdentityAuthenticator()
	keyFunc := auth.keyFunc(jwks)

	// Create a token with the correct kid
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = kid

	key, err := keyFunc(token)
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Verify it's an RSA public key
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestPingIdentityAuthenticator_KeyFunc_Errors(t *testing.T) {
	privateKey := generateTestRSAKey(t)
	jwks := createTestJWKSMapPingIdentity(&privateKey.PublicKey, "existing-kid")

	auth := NewPingIdentityAuthenticator()
	keyFunc := auth.keyFunc(jwks)

	tests := []struct {
		name          string
		setupToken    func() *jwt.Token
		errorContains string
	}{
		{
			name: "wrong signing method",
			setupToken: func() *jwt.Token {
				token := jwt.New(jwt.SigningMethodHS256)
				token.Header["kid"] = "existing-kid"
				return token
			},
			errorContains: "unexpected signing method",
		},
		{
			name: "missing kid",
			setupToken: func() *jwt.Token {
				return jwt.New(jwt.SigningMethodRS256)
			},
			errorContains: "missing 'kid'",
		},
		{
			name: "kid not found",
			setupToken: func() *jwt.Token {
				token := jwt.New(jwt.SigningMethodRS256)
				token.Header["kid"] = "unknown-kid"
				return token
			},
			errorContains: "not found in JWKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupToken()

			_, err := keyFunc(token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestPingIdentityClaims(t *testing.T) {
	now := time.Now()
	claims := &PingIdentityClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.pingone.com/12345678-1234-1234-1234-123456789abc",
			Subject:   "client-id-123",
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClientID: "client-id-123",
		Scope:    "openid profile",
	}

	issuer, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "https://auth.pingone.com/12345678-1234-1234-1234-123456789abc", issuer)

	subject, err := claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "client-id-123", subject)

	assert.Equal(t, "client-id-123", claims.ClientID)
	assert.Equal(t, "openid profile", claims.Scope)
}

func TestPingIdentityClaims_ClientCredentialsFlow(t *testing.T) {
	// Test client credentials flow where there's no 'sub' claim, only 'client_id'
	now := time.Now()
	claims := &PingIdentityClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.pingone.com/12345678-1234-1234-1234-123456789abc",
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			// No Subject field - this is typical for client credentials grant
		},
		ClientID: "bbe33b26-1e5e-455b-98a4-a291ddf50c03",
		Scope:    "openid",
	}

	issuer, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "https://auth.pingone.com/12345678-1234-1234-1234-123456789abc", issuer)

	// GetSubject will return empty for client credentials tokens
	subject, err := claims.GetSubject()
	assert.NoError(t, err)
	assert.Equal(t, "", subject)

	// But ClientID should be populated
	assert.Equal(t, "bbe33b26-1e5e-455b-98a4-a291ddf50c03", claims.ClientID)
	assert.Equal(t, "openid", claims.Scope)
}

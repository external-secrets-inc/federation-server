# Okta Federation Guide

This guide explains how to use Okta as an identity provider for the External Secrets Enterprise Federation Server.

## Overview

The Okta federation integration allows clients to authenticate to the federation server using OAuth2 access tokens issued by Okta. This enables:

- **Centralized identity management** through your Okta organization
- **Standard OAuth2/OIDC flows** for token acquisition
- **Fine-grained access control** using Authorization resources
- **Token-based authentication** without requiring mTLS

## Architecture

```
┌─────────────┐      1. Request Token       ┌──────────────┐
│   Client    │────────────────────────────>│     Okta     │
│ Application │                             │ Auth Server  │
└─────────────┘      2. Access Token        └──────────────┘
       │           <─────────────────────────        
       │                                            
       │   3. Request with Bearer Token             
       │                                            
       v                                            
┌─────────────────────────────────────────┐        
│     Federation Server                   │        
│  ┌──────────────────────────────────┐   │        
│  │  Auth Middleware                 │   │        
│  │  - OktaAuthenticator validates   │   │        
│  │  - Verifies signature with JWKS  │   │        
│  └──────────────────────────────────┘   │        
│  ┌──────────────────────────────────┐   │        
│  │  Authorization Check             │   │        
│  │  - Matches issuer + subject      │   │        
│  │  - Checks allowed resources      │   │        
│  └──────────────────────────────────┘   │        
└─────────────────────────────────────────┘        
```

## Prerequisites

1. **Okta Organization**: You need access to an Okta organization
2. **OAuth2 Service App**: Create a service app in Okta for machine-to-machine authentication
3. **Client Credentials**: Private key or client secret for your application

## Setup

### 1. Create Okta OAuth2 Service App

1. Sign in to your Okta Admin Console
2. Go to **Applications** > **Applications** > **Create App Integration**
3. Select **API Services** as the sign-in method
4. Configure the application:
   - **Grant Type**: Client Credentials
   - **Client Authentication**: `private_key_jwt` (recommended) or `client_secret_post`

### 2. Generate and Register Public Key (for private_key_jwt)

```bash
# Generate RSA key pair
openssl genrsa -out private-key.pem 2048
openssl rsa -in private-key.pem -pubout -out public-key.pem

# Convert to JWK format and register in Okta
# (Use Okta Admin Console or API to upload the public key)
```

### 3. Configure Authorization Server

1. In Okta Admin Console, go to **Security** > **API**
2. Select your authorization server (e.g., "default")
3. Note the **Issuer URI** (e.g., `https://dev-12345.okta.com/oauth2/default`)
4. Configure scopes as needed for your application

### 4. Deploy OktaFederation Resource

```yaml
apiVersion: identity.federation.external-secrets.io/v1alpha1
kind: OktaFederation
metadata:
  name: okta-prod
spec:
  domain: "https://dev-12345.okta.com"
  authorizationServerId: "default"  # or your custom auth server ID
```

### 5. Create Authorization Resource

```yaml
apiVersion: federation.external-secrets.io/v1alpha1
kind: Authorization
metadata:
  name: my-app-authorization
spec:
  federationRef:
    kind: OktaFederation
    name: okta-prod
  
  # Okta uses the OIDC subject type
  subject:
    oidc:
      # Must match: https://{domain}/oauth2/{authServerId}
      issuer: "https://dev-12345.okta.com/oauth2/default"
      # Must match the client ID from your Okta OAuth2 app
      subject: "0oabc123xyz456def"
  
  # Define which resources this client can access
  allowedClusterSecretStores:
    - "vault-backend"
    - "aws-secrets-manager"
  
  allowedGenerators: []  # Not yet supported for Okta
  allowedGeneratorStates: []
```

## Client Implementation

### Obtaining Access Token from Okta

#### Using Client Credentials with Private Key JWT

```go
package main

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "net/http"
    "net/url"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
)

func getOktaAccessToken(clientID, privateKeyPEM, oktaDomain, authServerID string) (string, error) {
    // Parse private key
    block, _ := pem.Decode([]byte(privateKeyPEM))
    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return "", err
    }
    
    // Create client assertion JWT
    now := time.Now()
    claims := jwt.MapClaims{
        "iss": clientID,
        "sub": clientID,
        "aud": fmt.Sprintf("%s/oauth2/%s/v1/token", oktaDomain, authServerID),
        "exp": now.Add(5 * time.Minute).Unix(),
        "iat": now.Unix(),
        "jti": uuid.New().String(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    clientAssertion, err := token.SignedString(privateKey)
    if err != nil {
        return "", err
    }
    
    // Request access token
    tokenURL := fmt.Sprintf("%s/oauth2/%s/v1/token", oktaDomain, authServerID)
    
    resp, err := http.PostForm(tokenURL, url.Values{
        "grant_type":            {"client_credentials"},
        "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
        "client_assertion":      {clientAssertion},
        "scope":                 {"your-required-scopes"},
    })
    
    // Parse response to get access_token
    // ...
    
    return accessToken, nil
}
```

### Making Requests to Federation Server

```go
func getSecretFromFederation(accessToken, federationURL, storeName, secretName string) ([]byte, error) {
    url := fmt.Sprintf("%s/secretstore/%s/secrets/%s", federationURL, storeName, secretName)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    // Add Bearer token
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("federation server returned status %d", resp.StatusCode)
    }
    
    return io.ReadAll(resp.Body)
}
```

## Token Structure

Okta access tokens contain the following relevant claims:

```json
{
  "ver": 1,
  "jti": "AT.unique-token-identifier",
  "iss": "https://dev-12345.okta.com/oauth2/default",
  "aud": "api://default",
  "iat": 1234567890,
  "exp": 1234571490,
  "cid": "0oabc123xyz456def",  // OAuth2 Client ID
  "uid": "00uabc123xyz",       // Okta User ID (if applicable)
  "scp": ["openid", "profile"], // Scopes
  "sub": "0oabc123xyz456def"   // Subject (equals cid for client credentials)
}
```

**Authorization Matching**:
- `iss` (issuer) → matches `Authorization.spec.subject.oidc.issuer`
- `sub` (subject) → matches `Authorization.spec.subject.oidc.subject`

## Current Limitations

### ❌ Generator Access Not Supported

Generator endpoints require `KubeAttributes` to track which Kubernetes workload is requesting credentials. Since Okta tokens don't inherently contain Kubernetes context, the following endpoints are **not yet supported**:

- `POST /generators/{namespace}/{kind}/{name}` - Generate credentials
- `DELETE /generators/{namespace}/{kind}/{name}` - Revoke self
- `POST /generators/{namespace}/revoke` - Revoke credentials

**Future Enhancement**: Add support via custom claims or request metadata.

### ✅ ClusterSecretStore Access Supported

The following endpoint **is fully supported**:

- `POST /secretstore/{storeName}/secrets/{secretName}` - Get secrets from ClusterSecretStore

## Security Considerations

1. **Token Lifetime**: Okta access tokens typically expire in 1 hour. Implement token refresh in your client.

2. **Private Key Security**: Store private keys securely (e.g., Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager).

3. **Principle of Least Privilege**: Grant only necessary ClusterSecretStore access in Authorization resources.

4. **Token Validation**: The federation server validates:
   - Signature using Okta's JWKS
   - Expiration with 2-minute clock skew leeway
   - Issuer matches configured federation
   - Subject matches authorization rules

5. **JWKS Caching**: The provider caches JWKS for 1 hour to reduce load on Okta's endpoints.

## Troubleshooting

### Token Validation Failures

```bash
# Check if JWKS endpoint is accessible
curl https://dev-12345.okta.com/oauth2/default/v1/keys

# Verify token signature at jwt.io
# Copy your token and paste into the debugger
```

### Authorization Not Found

```bash
# Verify Authorization resource exists
kubectl get authorizations.federation.external-secrets.io

# Check issuer and subject match exactly
kubectl get authorization my-app-authorization -o yaml
```

### Connection Issues

```bash
# Test federation server connectivity
curl -H "Authorization: Bearer $TOKEN" \
  https://federation-server:8080/secretstore/vault-backend/secrets/mysecret

# Check federation server logs
kubectl logs -n external-secrets deployment/external-secrets-federation-server
```

## Example: Complete Flow

```bash
# 1. Create OktaFederation
kubectl apply -f okta-federation.yaml

# 2. Create Authorization
kubectl apply -f okta-authorization.yaml

# 3. Client obtains token from Okta
TOKEN=$(curl -X POST https://dev-12345.okta.com/oauth2/default/v1/token \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$CLIENT_JWT" | jq -r '.access_token')

# 4. Client requests secret from federation server
curl -H "Authorization: Bearer $TOKEN" \
  https://federation-server:8080/secretstore/vault-backend/secrets/database-password
```

## Additional Resources

- [Okta OAuth 2.0 Documentation](https://developer.okta.com/docs/concepts/oauth-openid/)
- [Client Credentials Flow](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/)
- [Build JWT for Client Authentication](https://developer.okta.com/docs/guides/build-self-signed-jwt/java/main/)

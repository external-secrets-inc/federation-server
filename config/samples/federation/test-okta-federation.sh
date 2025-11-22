#!/bin/bash

# Configuration
CLIENT_ID="${OKTA_CLIENT_ID}"
PRIVATE_KEY_FILE="./key.pem"
OKTA_DOMAIN="https://trial-1038013.okta.com"
FEDERATION_SERVER="${FEDERATION_SERVER:-http://localhost:8000}"
CLUSTER_SECRET_STORE="${CLUSTER_SECRET_STORE:-vault-backend}"
SECRET_NAME="${SECRET_NAME:-my-secret}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Okta Federation Server Test ===${NC}"
echo ""

# Check if CLIENT_ID is set
if [ -z "$CLIENT_ID" ]; then
    echo -e "${RED}Error: OKTA_CLIENT_ID environment variable is not set${NC}"
    echo "Usage: export OKTA_CLIENT_ID='your_client_id' && ./test-okta-federation.sh"
    exit 1
fi

# Check if private key exists
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo -e "${RED}Error: Private key file not found: $PRIVATE_KEY_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}Step 1: Getting Okta Access Token${NC}"
echo "  Client ID: $CLIENT_ID"
echo "  Okta Domain: $OKTA_DOMAIN"
echo ""

# Generate JWT for client assertion
CURRENT_TIME=$(date +%s)
EXPIRY_TIME=$((CURRENT_TIME + 300))
JTI=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 32 | head -n 1)

# Create JWT header with kid
HEADER='{"alg":"RS256","typ":"JWT","kid":"ciBlgnncIabMCJIVTEbWgQV5tW318LvAN1TJFF4u0Hg"}'
HEADER_B64=$(echo -n "$HEADER" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create JWT payload
PAYLOAD="{\"iss\":\"$CLIENT_ID\",\"sub\":\"$CLIENT_ID\",\"aud\":\"$OKTA_DOMAIN/oauth2/v1/token\",\"exp\":$EXPIRY_TIME,\"iat\":$CURRENT_TIME,\"jti\":\"$JTI\"}"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create signature
SIGNATURE=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Construct JWT
CLIENT_ASSERTION="${HEADER_B64}.${PAYLOAD_B64}.${SIGNATURE}"

# Get access token from Okta
TOKEN_RESPONSE=$(curl -s -X POST "$OKTA_DOMAIN/oauth2/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$CLIENT_ASSERTION" \
  -d "scope=okta.apps.read")

# Check if we got an error
if echo "$TOKEN_RESPONSE" | grep -q "error"; then
    echo -e "${RED}Failed to get access token from Okta:${NC}"
    echo "$TOKEN_RESPONSE" | jq '.' 2>/dev/null || echo "$TOKEN_RESPONSE"
    exit 1
fi

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo -e "${RED}Failed to extract access token from response:${NC}"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ Successfully obtained Okta access token${NC}"
echo "  Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
echo ""

echo -e "${GREEN}Step 2: Calling Federation Server${NC}"
echo "  Federation Server: $FEDERATION_SERVER"
echo "  ClusterSecretStore: $CLUSTER_SECRET_STORE"
echo "  Secret Name: $SECRET_NAME"
echo "  Endpoint: POST /secretstore/$CLUSTER_SECRET_STORE/secrets/$SECRET_NAME"
echo ""

# Call federation server
FEDERATION_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "$FEDERATION_SERVER/secretstore/$CLUSTER_SECRET_STORE/secrets/$SECRET_NAME" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$FEDERATION_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$FEDERATION_RESPONSE" | head -n-1)

echo "HTTP Status: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓ Successfully fetched secret from federation server!${NC}"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"
else
    echo -e "${RED}✗ Failed to fetch secret (HTTP $HTTP_CODE)${NC}"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"
    exit 1
fi

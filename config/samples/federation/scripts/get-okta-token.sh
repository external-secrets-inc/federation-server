#!/bin/bash
# get-okta-token.sh
# Helper script to get an Okta access token using private_key_jwt client authentication

set -e

# Configuration from environment variables or defaults
CLIENT_ID="${OKTA_CLIENT_ID}"
PRIVATE_KEY_FILE="${OKTA_PRIVATE_KEY_PATH:-./private_key.pem}"
OKTA_DOMAIN="${OKTA_DOMAIN}"
AUTH_SERVER_ID="${OKTA_AUTH_SERVER_ID:-}"
SCOPES="${OKTA_SCOPES:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Validate required parameters
if [ -z "$CLIENT_ID" ]; then
    echo -e "${RED}Error: OKTA_CLIENT_ID environment variable is not set${NC}"
    echo "Usage: export OKTA_CLIENT_ID='your_client_id' && $0"
    exit 1
fi

if [ -z "$OKTA_DOMAIN" ]; then
    echo -e "${RED}Error: OKTA_DOMAIN environment variable is not set${NC}"
    echo "Usage: export OKTA_DOMAIN='https://trial-1038013.okta.com' && $0"
    exit 1
fi

if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo -e "${RED}Error: Private key file not found: $PRIVATE_KEY_FILE${NC}"
    exit 1
fi

# Construct token endpoint based on auth server
if [ -z "$AUTH_SERVER_ID" ] || [ "$AUTH_SERVER_ID" = "default" ]; then
    # Org authorization server
    TOKEN_ENDPOINT="$OKTA_DOMAIN/oauth2/v1/token"
else
    # Custom authorization server
    TOKEN_ENDPOINT="$OKTA_DOMAIN/oauth2/$AUTH_SERVER_ID/v1/token"
fi

echo -e "${GREEN}=== Okta Access Token Request ===${NC}"
echo "Client ID: $CLIENT_ID"
echo "Okta Domain: $OKTA_DOMAIN"
echo "Token Endpoint: $TOKEN_ENDPOINT"
echo "Private Key: $PRIVATE_KEY_FILE"
[ -n "$SCOPES" ] && echo "Scopes: $SCOPES"
echo ""

# Generate JWT for client assertion
CURRENT_TIME=$(date +%s)
EXPIRY_TIME=$((CURRENT_TIME + 300))
JTI=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 32 | head -n 1)

# Create JWT header (without kid)
HEADER='{"alg":"RS256","typ":"JWT"}'
HEADER_B64=$(echo -n "$HEADER" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create JWT payload
PAYLOAD="{\"iss\":\"$CLIENT_ID\",\"sub\":\"$CLIENT_ID\",\"aud\":\"$TOKEN_ENDPOINT\",\"exp\":$EXPIRY_TIME,\"iat\":$CURRENT_TIME,\"jti\":\"$JTI\"}"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create signature
SIGNATURE=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Construct JWT
CLIENT_ASSERTION="${HEADER_B64}.${PAYLOAD_B64}.${SIGNATURE}"

echo -e "${YELLOW}Generated client assertion JWT${NC}"
echo "Decode at https://jwt.io to verify claims"
echo ""

# Prepare POST data
POST_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$CLIENT_ASSERTION"

# Add scopes if specified
if [ -n "$SCOPES" ]; then
    POST_DATA="${POST_DATA}&scope=${SCOPES}"
fi

# Get access token from Okta
echo -e "${YELLOW}Requesting access token from Okta...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$POST_DATA")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✅ Successfully obtained access token!${NC}"
    echo ""
    
    # Parse response
    ACCESS_TOKEN=$(echo "$RESPONSE_BODY" | jq -r '.access_token' 2>/dev/null)
    EXPIRES_IN=$(echo "$RESPONSE_BODY" | jq -r '.expires_in' 2>/dev/null)
    
    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        echo "Access Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
        echo "Expires in: $EXPIRES_IN seconds"
        echo ""
        echo "To use this token, export it:"
        echo -e "${YELLOW}export ACCESS_TOKEN='$ACCESS_TOKEN'${NC}"
        echo ""
        echo "Or just output the token for piping:"
        echo "$ACCESS_TOKEN"
    else
        echo -e "${RED}Error: Could not parse access token from response${NC}"
        echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"
        exit 1
    fi
else
    echo -e "${RED}✗ Failed to get access token (HTTP $HTTP_CODE)${NC}"
    echo ""
    echo "Response:"
    echo "$RESPONSE_BODY" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY"
    exit 1
fi

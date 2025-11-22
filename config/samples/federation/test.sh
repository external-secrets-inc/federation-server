#!/bin/bash

# Configuration
CLIENT_ID="${OKTA_CLIENT_ID}"
PRIVATE_KEY_FILE="./key.pem"
OKTA_DOMAIN="https://trial-1038013.okta.com"

# Check if CLIENT_ID is set
if [ -z "$CLIENT_ID" ]; then
    echo "Error: OKTA_CLIENT_ID environment variable is not set"
    echo "Usage: export OKTA_CLIENT_ID='your_client_id' && ./test.sh"
    exit 1
fi

echo "Using CLIENT_ID: $CLIENT_ID"

# Verify the private key and extract public key to compare with Okta
echo ""
echo "=== Verifying Private Key ==="
openssl rsa -in "$PRIVATE_KEY_FILE" -check -noout 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Invalid private key file"
    exit 1
fi

echo "Extracting public key from your private key..."
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout 2>/dev/null | openssl pkey -pubin -text -noout | grep -A 10 "Modulus:" | head -n 5
echo ""
echo "Compare the above modulus with the 'n' parameter in your Okta JWK."
echo "If they don't match, the keys are different!"
echo ""

CURRENT_TIME=$(date +%s)
EXPIRY_TIME=$((CURRENT_TIME + 300))
JTI=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 32 | head -n 1)

# Create JWT header with kid
HEADER='{"alg":"RS256","typ":"JWT","kid":"ciBlgnncIabMCJIVTEbWgQV5tW318LvAN1TJFF4u0Hg"}'
HEADER_B64=$(echo -n "$HEADER" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create JWT payload
# Audience must be the token endpoint URL
PAYLOAD=$(cat <<EOF
{"iss":"$CLIENT_ID","sub":"$CLIENT_ID","aud":"$OKTA_DOMAIN/oauth2/v1/token","exp":$EXPIRY_TIME,"iat":$CURRENT_TIME,"jti":"$JTI"}
EOF
)
PAYLOAD_B64=$(echo -n "$PAYLOAD" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Create signature
SIGNATURE=$(echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')

# Construct JWT
CLIENT_ASSERTION="${HEADER_B64}.${PAYLOAD_B64}.${SIGNATURE}"

echo "JWT Header (decoded): $HEADER"
echo "JWT Payload (decoded): {\"iss\":\"$CLIENT_ID\",\"sub\":\"$CLIENT_ID\",\"aud\":\"$OKTA_DOMAIN/oauth2/v1/token\",\"exp\":$EXPIRY_TIME,\"iat\":$CURRENT_TIME,\"jti\":\"$JTI\"}"
echo ""
echo "Full JWT (copy this to jwt.io to debug):"
echo "$CLIENT_ASSERTION"
echo ""
echo "Verifying JWT signature locally..."
# Verify signature locally
echo -n "${HEADER_B64}.${PAYLOAD_B64}" | openssl dgst -sha256 -verify <(openssl rsa -in "$PRIVATE_KEY_FILE" -pubout 2>/dev/null) -signature <(echo "$SIGNATURE" | tr '_-' '/+' | base64 -d) 2>&1
echo ""
echo "Making request to: $OKTA_DOMAIN/oauth2/v1/token"
echo ""

# Make request
curl -v -X POST "$OKTA_DOMAIN/oauth2/v1/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$CLIENT_ASSERTION" \
  -d "scope=okta.apps.read"
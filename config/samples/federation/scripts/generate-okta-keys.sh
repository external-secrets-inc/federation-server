#!/bin/bash
# generate-okta-keys.sh
# Helper script to generate RSA key pair for Okta OAuth2 authentication

set -e

echo "=== Okta RSA Key Pair Generator ==="
echo ""

# Check for required tools
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl is required but not installed. Aborting." >&2; exit 1; }

# Generate private key
echo "Generating 2048-bit RSA private key..."
openssl genrsa -out private_key.pem 2048

# Extract public key
echo "Extracting public key..."
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Verify the key
echo "Verifying key..."
openssl rsa -in private_key.pem -check -noout

echo ""
echo "✅ Key pair generated successfully!"
echo ""
echo "Files created:"
echo "  - private_key.pem (KEEP THIS SECURE!)"
echo "  - public_key.pem (Register this in Okta)"
echo ""
echo "Next steps:"
echo "1. Go to your Okta application settings"
echo "2. Navigate to 'Client Credentials' section"
echo "3. Select 'Public key / Private key' authentication"
echo "4. Click 'Add key' and choose 'PEM'"
echo "5. Copy and paste the content of public_key.pem:"
echo ""
cat public_key.pem
echo ""
echo "6. Save the key in Okta"
echo "7. Note the Key ID (kid) that Okta generates"
echo ""
echo "⚠️  IMPORTANT: Keep private_key.pem secure and never commit it to version control!"

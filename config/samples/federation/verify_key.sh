#!/bin/bash

# Decode the 'n' (modulus) from your Okta JWK and compare with your private key

OKTA_N="8p7P8vn3qk-3jI505PPP5TVmQ5eDzaNb9KB1CTKcsciGfCsow-EMHom2vm02q2r0DD7CTwz_4vrorIY1F8gIkyOnSuUh9uI2f5YJqkl3_--wdPpMEzxp9hBpNjr24tY9MSmD6j1-RkB_bHAblf-sItTFN1x4XFnEyx-P2hZrxQNfRgKHFtPh-akEKKzCE4Hn_Q_wRDhvZ3-sO940x9FeVyuHIOS_2b9e1ZBRFk52p50eU_S6pWj6v-BqZuwPZxpI-OMb2BG1Fk_YY_1PqL4HhA5e2GSX7cgxk5dOd1Fkt0Iw-7rt3zf9xhvZjh2oa8thcyM28PyXLGCuyISQosw4VQ"

echo "=== Okta JWK Public Key ==="
echo "Decoding modulus (n) from Okta..."

# Convert base64url to base64 and decode
OKTA_N_BASE64=$(echo -n "$OKTA_N" | tr '_-' '/+')
# Add padding if needed
PAD_LEN=$((4 - ${#OKTA_N_BASE64} % 4))
if [ $PAD_LEN -lt 4 ]; then
    OKTA_N_BASE64="${OKTA_N_BASE64}$(printf '%*s' $PAD_LEN '' | tr ' ' '=')"
fi

echo "$OKTA_N_BASE64" | base64 -d 2>/dev/null | xxd -p -c 256 | head -c 60
echo "..."

echo ""
echo "=== Your Private Key's Public Modulus ==="
echo "Extracting from key.pem..."
openssl rsa -in ./key.pem -modulus -noout 2>/dev/null | sed 's/Modulus=//' | head -c 60
echo "..."

echo ""
echo ""
echo "If the hex values above don't match, your private key doesn't match the public key in Okta!"

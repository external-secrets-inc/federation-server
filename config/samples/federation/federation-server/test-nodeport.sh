#!/bin/bash
# Script to connect to federation server with Kubernetes service account token

set -e

echo "Getting service account token..."
TOKEN=$(kubectl create token federation-sa -n federation-example)

echo "Getting CA certificate..."
CA_CERT=$(kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="kind-federation-source")].cluster.certificate-authority-data}')

echo "Creating JSON payload..."
JSON_PAYLOAD=$(jq -n \
  --arg cert "$CA_CERT" \
  '{
    "ca.crt": $cert
  }')

echo "$JSON_PAYLOAD" > payload.json
echo "Payload saved to payload.json"

echo "Sending request to federation server..."
curl -X POST \
  http://localhost:30080/generators/federation-example/Fake/federation-generator \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "@payload.json"

rm ./payload.json || true
echo "Script execution completed"

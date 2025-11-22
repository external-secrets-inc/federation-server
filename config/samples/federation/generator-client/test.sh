#!/bin/bash

set -e
set -x

# Create the token secret
./config/samples/federation/generator-client/create-federation-token.sh

# Apply the Federation generator configuration
kubectl apply -f config/samples/federation/generator-client/federation-generator.yaml

# Apply the ExternalSecret
kubectl apply -f config/samples/federation/generator-client/external-secret.yaml

# Wait for the ExternalSecret to be synced
echo "Waiting for ExternalSecret to be synced..."
kubectl wait --for=condition=Ready externalsecret/federation-external-secret -n federation-example --timeout=60s

# Get the ExternalSecret status
kubectl get externalsecret federation-external-secret -n federation-example -o yaml

# Get the Secret created by the ExternalSecret
kubectl get secret federation-external-secret -n federation-example -o yaml

echo "Test completed successfully!"

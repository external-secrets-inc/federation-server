#!/bin/bash
set -e

SOURCE_CONTEXT="kind-federation-source"

# Create the token from the source cluster
echo "Creating service account token from $SOURCE_CONTEXT cluster..."
TOKEN=$(kubectl --context=$SOURCE_CONTEXT create token federation-sa -n federation-example)

# Get the CA certificate from the source cluster
echo "Getting CA certificate from $SOURCE_CONTEXT cluster..."
CA_CERT=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$SOURCE_CONTEXT\")].cluster.certificate-authority-data}")

# Determine which cluster to create the secret in
# This example creates it in the current context, but you can specify a target context if needed
echo "Creating secret with token and ca.cert..."
kubectl delete secret federation-token --ignore-not-found
kubectl create secret generic federation-token \
  --from-literal=token=$TOKEN \
  --from-literal=ca.crt=$CA_CERT

echo "Secret 'federation-token' created with token and ca.crt from $SOURCE_CONTEXT cluster"

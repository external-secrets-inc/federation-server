#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPAT_FILE=${COMPAT_FILE:-"${ROOT_DIR}/docs/compatibility.json"}
MATRIX_INDEX=${MATRIX_INDEX:-0}

# Resolve versions from environment or compatibility matrix
if [[ -z "${CORE_CHART:-}" || -z "${CORE_VERSION:-}" || -z "${FED_CHART:-}" || -z "${FED_VERSION:-}" ]]; then
  if [[ ! -f "${COMPAT_FILE}" ]]; then
    echo "compatibility file ${COMPAT_FILE} not found; set CORE_CHART/CORE_VERSION/FED_CHART/FED_VERSION manually" >&2
    exit 1
  fi

  readarray -t MATRIX_VALUES < <(python - <<'PY'
import json, os, sys
path = os.environ.get("COMPAT_FILE")
idx = int(os.environ.get("MATRIX_INDEX", "0"))
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except FileNotFoundError:
    sys.exit(f"{path} not found")
if idx < 0 or idx >= len(data):
    sys.exit(f"matrix index {idx} out of range (len={len(data)})")
entry = data[idx]
required = ["core_chart", "core_version", "federation_chart", "federation_version"]
missing = [key for key in required if key not in entry]
if missing:
    sys.exit(f"missing keys in entry {idx}: {', '.join(missing)}")
for key in required:
    print(entry[key])
PY
  )

  CORE_CHART=${CORE_CHART:-${MATRIX_VALUES[0]}}
  CORE_VERSION=${CORE_VERSION:-${MATRIX_VALUES[1]}}
  FED_CHART=${FED_CHART:-${MATRIX_VALUES[2]}}
  FED_VERSION=${FED_VERSION:-${MATRIX_VALUES[3]}}
fi

if [[ -z "${CORE_CHART}" || -z "${CORE_VERSION}" || -z "${FED_CHART}" || -z "${FED_VERSION}" ]]; then
  echo "core/federation chart versions must be set" >&2
  exit 1
fi

echo "Running contract test with:" \
  && echo "  CORE_CHART=${CORE_CHART}" \
  && echo "  CORE_VERSION=${CORE_VERSION}" \
  && echo "  FED_CHART=${FED_CHART}" \
  && echo "  FED_VERSION=${FED_VERSION}"

echo "Installing core chart..."
helm upgrade --install external-secrets "${CORE_CHART}" \
  --namespace external-secrets --create-namespace \
  --version "${CORE_VERSION}" \
  --wait --timeout 5m

echo "Installing federation chart..."
helm upgrade --install federation "${FED_CHART}" \
  --namespace federation --create-namespace \
  --version "${FED_VERSION}" \
  --set crds.create=true \
  --wait --timeout 5m

echo "Waiting for core deployment availability..."
if ! kubectl get deploy -n external-secrets -l app.kubernetes.io/name=external-secrets -o name | grep -q "."; then
  echo "no external-secrets deployment found in namespace external-secrets" >&2
  exit 1
fi
kubectl wait --for=condition=Available deployment -l app.kubernetes.io/name=external-secrets -n external-secrets --timeout=180s

echo "Waiting for federation deployment availability..."
if ! kubectl get deploy -n federation -l app.kubernetes.io/name=federation -o name | grep -q "."; then
  echo "no federation deployment found in namespace federation" >&2
  exit 1
fi
kubectl wait --for=condition=Available deployment -l app.kubernetes.io/name=federation -n federation --timeout=180s

echo "Validating federation CRDs present..."
kubectl get crd federations.generators.external-secrets.io
kubectl get crd authorizedidentities.federation.external-secrets.io
kubectl get crd authorizations.federation.external-secrets.io

cat <<'EOF'
Contract test completed:
- Core and federation charts installed and controllers are available.
- Federation CRDs are registered.
EOF

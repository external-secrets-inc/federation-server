# Compatibility Matrix

This repository validates released federation charts against the enterprise (core) chart. Each entry should be reflected in CI contract tests and updated when a new pair ships.

| Core chart | Core version | Federation chart | Federation version | Notes |
| --- | --- | --- | --- | --- |
| `oci://us-central1-docker.pkg.dev/external-secrets-inc-registry/public/charts/external-secrets` | `1.24.0` | `oci://us-central1-docker.pkg.dev/external-secrets-inc-registry/public/charts/federation` | `1.24.0` | Lockstep minor versions during cutover |

To add a new pair, update both this table and `docs/compatibility.json`. CI consumes `docs/compatibility.json` for the contract workflow.

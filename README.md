# external-secrets-federation (Phase 1 bootstrap)

This repo hosts the federation CRDs, controllers, and HTTP/mTLS server split out of the enterprise controller.

## Bootstrap
- Go 1.25.4+.
- `go mod tidy` is wired to the local enterprise tree via `replace` for now; swap the `require github.com/external-secrets/external-secrets v0.0.0-20251122115546-112c9c0c7d67` to a tagged version and drop the `replace` block once a published tag exists.

## Build & test
- Build: `GOFLAGS=-mod=mod go build ./cmd/federation`.
- Unit tests: `GOFLAGS=-mod=mod go test ./...` (uses the local replace block).
- Static check for stray relative imports: `rg '../external-secrets'` (expect only go.mod replaces until a tag exists).

## CRDs
- CRDs live under `config/crds/bases/`. Regenerate with controller-gen (from this repo root):
  ```
  controller-gen crd:crdVersions=v1 paths=./apis/... output:crd:artifacts:config=config/crds/bases
  ```

## Assets moved in Phase 1
- Federation controllers: `pkg/enterprise/controllers/federation/**`
- Federation server + deps/store/auth: `pkg/enterprise/federation/**`
- APIs: `apis/enterprise/federation/**` (including identity)
- CRDs: `config/crds/bases/*federation*`, identity CRDs
- Samples: `config/samples/federation/**`
- Helm bits: `deploy/charts/federation/templates/**`

## Notes
- The federation generator remains in the core repo; this binary exposes the federation server and controllers only.
- Flags mirror the in-tree wiring: `--server-port`, `--server-tls-port`, `--enable-federation-tls`, `--controller-class`, `--enable-flood-gate`, `--spire-agent-socket-path`, metrics/probe addresses, and leader election.

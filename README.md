# external-secrets-federation

This repo hosts the federation CRDs, controllers, and HTTP/mTLS server split out of the enterprise controller.

## Bootstrap
- Go 1.25.4+, Docker, Helm 3.16+, controller-gen in `$PATH`.
- `go mod tidy` uses a `replace` to the enterprise repo at commit `112c9c0c7d67`. Swap the `require github.com/external-secrets/external-secrets v0.0.0-20251122115546-112c9c0c7d67` to a tagged version and drop the `replace` once a published tag exists.

## Build, test, release
- Build: `make build` (binary at `bin/federation`).
- Unit tests: `make test` (sets `GOFLAGS=-mod=mod`).
- CRDs: `make crds` regenerates `config/crds/bases` and the chart CRDs are kept under `deploy/charts/federation/crds/`.
- Docker image: `make docker-build IMAGE=ghcr.io/<repo>/federation-server:<tag>`.
- Helm chart: `make helm-lint` and `make helm-package` (outputs to `dist/`).
- Release: `make release-snapshot` locally or use the tag-triggered GitHub Action (`.github/workflows/release.yaml`) which runs GoReleaser (archives, image build with `skip_push`, Helm chart package).

## Assets moved to this repo from external-secrets-enterprise
- Federation controllers: `pkg/enterprise/controllers/federation/**`
- Federation server + deps/store/auth: `pkg/enterprise/federation/**`
- APIs: `apis/enterprise/federation/**` (including identity)
- CRDs: `config/crds/bases/*federation*`, identity CRDs
- Samples: `config/samples/federation/**`
- Helm chart: `deploy/charts/federation/**`

## Notes
- The federation generator remains in the core repo; this binary exposes the federation server and controllers only.
- Flags mirror the in-tree wiring: `--server-port`, `--server-tls-port`, `--enable-federation-tls`, `--controller-class`, `--enable-flood-gate`, `--spire-agent-socket-path`, metrics/probe addresses, and leader election.

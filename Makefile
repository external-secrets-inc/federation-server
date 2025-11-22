SHELL := /bin/bash

GO ?= go
GOFLAGS ?= -mod=mod
BIN ?= bin/federation
IMAGE ?= ghcr.io/external-secrets-inc/federation-server:dev
DOCKERFILE ?= Dockerfile
CHART ?= deploy/charts/federation
DIST ?= dist
GORELEASER ?= goreleaser
CONTROLLER_GEN ?= controller-gen

.PHONY: build
build: $(BIN)

$(BIN):
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/federation

.PHONY: test
test:
	GOFLAGS=$(GOFLAGS) $(GO) test ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: crds
crds:
	$(CONTROLLER_GEN) crd:crdVersions=v1 paths=./apis/... output:crd:artifacts:config=config/crds/bases

.PHONY: helm-lint
helm-lint:
	helm lint $(CHART)

.PHONY: helm-package
helm-package:
	mkdir -p $(DIST)
	helm package $(CHART) -d $(DIST)

.PHONY: docker-build
docker-build:
	docker build --build-arg TARGETOS=linux --build-arg TARGETARCH=amd64 -t $(IMAGE) -f $(DOCKERFILE) .

.PHONY: docker-buildx
docker-buildx:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE) -f $(DOCKERFILE) .

.PHONY: docker-push
docker-push:
	docker push $(IMAGE)

.PHONY: release-snapshot
release-snapshot:
	$(GORELEASER) release --clean --skip=sign --skip=publish --snapshot

.PHONY: release
release:
	$(GORELEASER) release --clean

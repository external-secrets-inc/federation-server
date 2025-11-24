SHELL := /bin/bash

GO ?= go
GOFLAGS ?= -mod=mod
BIN ?= bin/federation
REGISTRY ?= us-central1-docker.pkg.dev/external-secrets-inc-registry/external
IMAGE_NAME ?= federation-server
IMAGE ?= $(REGISTRY)/$(IMAGE_NAME)
VERSION ?= dev
DOCKERFILE ?= Dockerfile
CHART ?= deploy/charts/federation
DIST ?= dist
HELM_REPO ?= oci://us-central1-docker.pkg.dev/external-secrets-inc-registry/public/charts
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
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
	docker build --build-arg TARGETOS=linux --build-arg TARGETARCH=amd64 -t $(IMAGE):$(VERSION) -f $(DOCKERFILE) .

.PHONY: docker-buildx
docker-buildx:
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(IMAGE):$(VERSION) -f $(DOCKERFILE) .

.PHONY: docker-buildx-push
docker-buildx-push:
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(IMAGE):$(VERSION) -f $(DOCKERFILE) --push .

.PHONY: docker-push
docker-push:
	docker push $(IMAGE):$(VERSION)

.PHONY: helm-package
helm-package:
	mkdir -p $(DIST)
	helm package $(CHART) -d $(DIST) --version $(VERSION) --app-version $(VERSION)

.PHONY: helm-push
helm-push: helm-package
	helm push $(DIST)/federation-$(VERSION).tgz $(HELM_REPO)

CONTRACT_MATRIX_INDEX ?= 0

.PHONY: contract-test
contract-test:
	MATRIX_INDEX=$(CONTRACT_MATRIX_INDEX) bash hack/contract-test.sh

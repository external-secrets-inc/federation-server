# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25.4
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot
ARG TARGETOS
ARG TARGETARCH

FROM golang:${GO_VERSION} AS builder
WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
	go build -o /workspace/bin/federation ./cmd/federation

FROM ${BASE_IMAGE}
USER nonroot:nonroot
COPY --from=builder /workspace/bin/federation /usr/local/bin/federation

ENTRYPOINT ["/usr/local/bin/federation"]

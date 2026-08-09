# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm@sha256:4ab356d189e1dc845de28e43a7e62813f64f22308d3dea2217b570b397a2b735 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/authd ./cmd/authd
RUN cd examples && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./internal/healthcheck

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/authd /authd
COPY --from=builder /out/healthcheck /healthcheck
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/authd"]

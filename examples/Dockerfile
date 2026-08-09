FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build
ARG EXAMPLE
WORKDIR /src
COPY . .
RUN cd examples && CGO_ENABLED=0 go build -o /out/example ./"${EXAMPLE}" && \
	CGO_ENABLED=0 go build -o /out/healthcheck ./internal/healthcheck && \
	CGO_ENABLED=0 go build -o /out/democtl ./cmd/democtl

FROM build AS test
WORKDIR /src/examples
ENTRYPOINT ["go", "test"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:37d3baf4e657ce79c144b69b69f60b8542f366a64fb7a49bd99f5444ef008bb0 AS demo-tools
COPY --from=build /out/democtl /democtl
ENTRYPOINT ["/democtl"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:37d3baf4e657ce79c144b69b69f60b8542f366a64fb7a49bd99f5444ef008bb0
COPY --from=build /out/example /example
COPY --from=build /out/healthcheck /healthcheck
ENTRYPOINT ["/example"]

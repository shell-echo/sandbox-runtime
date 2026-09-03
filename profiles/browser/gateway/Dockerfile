ARG GO_IMAGE=docker.io/library/golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc

FROM $GO_IMAGE AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/browser-egress-gateway ./cmd/browser-egress-gateway
COPY provider/browser/network/gateway ./provider/browser/network/gateway

RUN CGO_ENABLED=0 GOOS=linux go build \
	-buildvcs=false \
	-trimpath \
	-ldflags='-s -w -buildid=' \
	-o /out/browser-egress-gateway \
	./cmd/browser-egress-gateway

FROM scratch

COPY --from=build /out/browser-egress-gateway /browser-egress-gateway

LABEL org.opencontainers.image.title="sandbox-runtime Browser egress gateway" \
      org.opencontainers.image.description="Provider-local restricted Browser egress enforcement; not a public Runtime Gateway" \
      org.opencontainers.image.source="https://github.com/shell-echo/sandbox-runtime" \
      org.opencontainers.image.version="browser-egress-gateway-v1" \
      io.github.shell-echo.sandbox-runtime.component="browser-egress-gateway-v1"

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER 65532:65532
WORKDIR /

HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=5 \
	CMD ["/browser-egress-gateway", "healthcheck"]

ENTRYPOINT ["/browser-egress-gateway"]
CMD ["serve"]

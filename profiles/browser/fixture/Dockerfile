ARG GO_IMAGE=docker.io/library/golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc

FROM $GO_IMAGE AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/browser-egress-fixture ./cmd/browser-egress-fixture

RUN CGO_ENABLED=0 GOOS=linux go build \
    -buildvcs=false \
    -trimpath \
    -ldflags='-s -w -buildid=' \
    -o /out/browser-egress-fixture \
    ./cmd/browser-egress-fixture

FROM scratch

COPY --from=build /out/browser-egress-fixture /browser-egress-fixture

USER 65532:65532
ENTRYPOINT ["/browser-egress-fixture"]

# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
# Pin the multi-platform base indexes. Updating either digest is a reviewed
# supply-chain change and must regenerate the release profile/SBOM.
FROM golang:${GO_VERSION}-alpine@sha256:51a7c389a5ddaf82f527191a1e9bff9928655130a44e4975dd1d7e0acf59f1ae AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandbox-runtime .

FROM alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

WORKDIR /app

RUN apk add --no-cache ca-certificates

ARG USERNAME=sandbox
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN set -eux; \
    addgroup -g ${USER_GID} ${USERNAME}; \
    adduser -u ${USER_UID} -G ${USERNAME} -D -H -s /sbin/nologin ${USERNAME}; \
    chown ${USERNAME}:${USERNAME} /app

COPY --from=builder /out/sandbox-runtime /usr/local/bin/sandbox-runtime

USER ${USER_UID}:${USER_GID}

ENTRYPOINT ["sandbox-runtime"]
CMD ["serve"]

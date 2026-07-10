# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandbox-runtime .

FROM alpine:3

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

ARG USERNAME=sandbox
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN set -eux; \
    addgroup -g ${USER_GID} ${USERNAME}; \
    adduser -u ${USER_UID} -G ${USERNAME} -D -H -s /sbin/nologin ${USERNAME}; \
    chown ${USERNAME}:${USERNAME} /app

COPY --from=builder /out/sandbox-runtime /usr/local/bin/sandbox-runtime

USER ${USERNAME}

EXPOSE 8080

ENTRYPOINT ["sandbox-runtime"]
CMD ["serve"]

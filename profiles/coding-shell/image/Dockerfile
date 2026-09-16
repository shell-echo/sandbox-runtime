ARG BASE_IMAGE=docker.io/library/alpine
ARG BASE_IMAGE_DIGEST

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST} AS prepared

COPY --chmod=0555 terminal-broker /usr/local/libexec/sandbox-runtime/terminal-broker

# Normalize every build-owned path. The pinned upstream files retain their
# upstream timestamps; the final scratch repack has no mutable inherited image
# configuration.
RUN mkdir -p /inputs /workspace /outputs /tmp && \
    chmod 0555 /inputs && \
    chmod 0770 /workspace /outputs /tmp && \
    chown 65532:65532 /workspace /outputs /tmp && \
    touch -d @0 /usr/local/libexec/sandbox-runtime/terminal-broker && \
    find / -xdev -type d \
        ! -path '/dev*' \
        ! -path '/proc*' \
        ! -path '/sys*' \
        -exec touch -d @0 {} +

FROM scratch

COPY --link --from=prepared / /

ARG VCS_REF=unknown
ARG SOURCE_DATE_EPOCH=0
ARG BASE_IMAGE
ARG BASE_IMAGE_DIGEST

LABEL org.opencontainers.image.title="sandbox-runtime coding/shell guest" \
      org.opencontainers.image.description="Provider-local coding/shell guest; not a caller or public Gateway" \
      org.opencontainers.image.source="https://github.com/shell-echo/sandbox-runtime" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="sandbox-runtime-coding-shell-v1" \
      org.opencontainers.image.created="1970-01-01T00:00:00Z" \
      org.opencontainers.image.base.name="${BASE_IMAGE}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.profile="sandbox-runtime-coding-shell-v1" \
      io.github.shell-echo.sandbox-runtime.terminal-broker-path="/usr/local/libexec/sandbox-runtime/terminal-broker" \
      io.github.shell-echo.sandbox-runtime.provenance.source-digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.provenance.source-date-epoch="${SOURCE_DATE_EPOCH}"

ENV HOME=/workspace \
    SHELL=/bin/sh \
    TMPDIR=/tmp

USER 65532:65532
WORKDIR /workspace

CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]

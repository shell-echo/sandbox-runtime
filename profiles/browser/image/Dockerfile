ARG BASE_IMAGE=docker.io/chromedp/headless-shell
ARG BASE_IMAGE_DIGEST=sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST} AS upstream

FROM upstream AS prepared

COPY --chmod=0555 entrypoint.sh /usr/local/bin/browser-runtime
COPY workspace/.keep /workspace/.keep

# Docker otherwise stamps some rootfs directories with the build clock, which
# makes an otherwise digest-pinned repack non-reproducible. The mounted kernel
# filesystems are excluded because they are not copied into the final image.
RUN find / -xdev -type d \
	! -path '/dev*' \
	! -path '/proc*' \
	! -path '/sys*' \
	-exec touch -d @0 {} +

FROM scratch

# Repack the pinned upstream rootfs so its unsafe 0.0.0.0/socat entrypoint and
# inherited wildcard endpoint metadata are not part of this image's configuration.
COPY --link --from=prepared / /

ARG VCS_REF=unknown
ARG SOURCE_DATE_EPOCH=0
ARG BASE_IMAGE
ARG BASE_IMAGE_DIGEST

LABEL org.opencontainers.image.title="sandbox-runtime browser guest" \
      org.opencontainers.image.description="Provider-local browser guest; not a public Gateway" \
      org.opencontainers.image.source="https://github.com/shell-echo/sandbox-runtime" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="sandbox-runtime-browser-v1" \
      org.opencontainers.image.created="1970-01-01T00:00:00Z" \
      org.opencontainers.image.base.name="${BASE_IMAGE}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.profile="sandbox-runtime-browser-v1" \
      io.github.shell-echo.sandbox-runtime.provenance.source-digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.provenance.source-date-epoch="${SOURCE_DATE_EPOCH}"

ENV HOME=/tmp/browser-home \
    XDG_CACHE_HOME=/tmp/browser-cache \
    XDG_CONFIG_HOME=/tmp/browser-config \
    XDG_RUNTIME_DIR=/tmp/browser-runtime \
    BROWSER_RUNTIME_ALLOW_UNSANDBOXED=0

USER 1000:1000
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/browser-runtime"]

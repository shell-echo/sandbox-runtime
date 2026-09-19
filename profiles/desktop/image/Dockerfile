ARG BASE_IMAGE=docker.io/library/alpine
ARG BASE_IMAGE_DIGEST=sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST} AS prepared

ARG PACKAGE_ARCHIVE_SET_SHA256
ARG INSTALLED_SET_SHA256=6b5fc1ece685456ed20f474c9af9547c597210f9105f7f12e9cf21d8377db4b5

RUN printf '%s\n' \
      'https://dl-cdn.alpinelinux.org/alpine/v3.23/main' \
      'https://dl-cdn.alpinelinux.org/alpine/v3.23/community' \
      > /etc/apk/repositories && \
    apk update >/dev/null && \
    mkdir -p /tmp/apks && \
    apk fetch --recursive --output /tmp/apks \
      xvfb=21.1.23-r0 \
      openbox=3.6.1-r8 \
      xterm=403-r0 \
      xdotool=4.20251130.1-r0 \
      xdpyinfo=1.4.0-r0 \
      xset=1.2.5-r1 \
      xwd=1.0.9-r2 \
      font-dejavu=2.37-r6 >/dev/null && \
    archive_digest="$(find /tmp/apks -type f -exec sha256sum {} \; | LC_ALL=C sort -k2 | sha256sum | cut -d' ' -f1)" && \
    test "${archive_digest}" = "${PACKAGE_ARCHIVE_SET_SHA256}" && \
    apk add --no-network /tmp/apks/*.apk >/dev/null && \
    installed_digest="$(apk info -v | LC_ALL=C sort | sha256sum | cut -d' ' -f1)" && \
    test "${installed_digest}" = "${INSTALLED_SET_SHA256}" && \
    rm -rf /tmp/apks /var/cache/apk/* /var/cache/fontconfig/* && \
    rm -f /var/log/apk.log

COPY --chmod=0555 desktop-broker /usr/local/libexec/sandbox-runtime/desktop-broker
COPY --chmod=0555 entrypoint.sh /usr/local/bin/desktop-runtime

RUN mkdir -p /inputs /workspace /outputs /tmp && \
    addgroup -g 1000 -S desktop && \
    adduser -u 1000 -S -D -H -h /tmp/desktop-home -s /bin/sh -G desktop desktop && \
    chmod 0555 /inputs && \
    chmod 0770 /workspace /outputs && \
    chmod 1777 /tmp && \
    chown 1000:1000 /workspace /outputs && \
    find / -xdev \
      ! -path '/dev*' \
      ! -path '/proc*' \
      ! -path '/sys*' \
      ! -path '/etc/hosts' \
      ! -path '/etc/hostname' \
      ! -path '/etc/resolv.conf' \
      ! -type l \
      -exec touch -d @0 {} + && \
    find / -xdev \
      ! -path '/dev*' \
      ! -path '/proc*' \
      ! -path '/sys*' \
      -type l \
      -exec touch -h -d @0 {} +

FROM scratch

COPY --link --from=prepared / /

ARG VCS_REF=unknown
ARG SOURCE_DATE_EPOCH=0
ARG BASE_IMAGE
ARG BASE_IMAGE_DIGEST
ARG PACKAGE_ARCHIVE_SET_SHA256

LABEL org.opencontainers.image.title="sandbox-runtime Desktop guest" \
      org.opencontainers.image.description="Provider-local Desktop guest; no public Gateway" \
      org.opencontainers.image.source="https://github.com/shell-echo/sandbox-runtime" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="sandbox-runtime-desktop-v1" \
      org.opencontainers.image.created="1970-01-01T00:00:00Z" \
      org.opencontainers.image.base.name="${BASE_IMAGE}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.profile="sandbox-runtime-desktop-v1" \
      io.github.shell-echo.sandbox-runtime.desktop-broker-protocol="sandbox.runtime/desktop-broker/v1" \
      io.github.shell-echo.sandbox-runtime.desktop-broker-path="/usr/local/libexec/sandbox-runtime/desktop-broker" \
      io.github.shell-echo.sandbox-runtime.package-archive-set-digest="sha256:${PACKAGE_ARCHIVE_SET_SHA256}" \
      io.github.shell-echo.sandbox-runtime.provenance.source-digest="${BASE_IMAGE_DIGEST}" \
      io.github.shell-echo.sandbox-runtime.provenance.source-date-epoch="${SOURCE_DATE_EPOCH}"

ENV DISPLAY=:99 \
    HOME=/tmp/desktop-home \
    XDG_CACHE_HOME=/tmp/desktop-cache \
    XDG_CONFIG_HOME=/tmp/desktop-config \
    XDG_RUNTIME_DIR=/tmp/desktop-runtime

USER 1000:1000
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/desktop-runtime"]

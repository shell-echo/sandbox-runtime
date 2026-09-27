FROM alpine@sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c

ARG VCS_REF
ARG ROLE_TARGET

LABEL io.github.shell-echo.sandbox-runtime.phase6-candidate="local-only-non-release" \
      io.github.shell-echo.sandbox-runtime.source-revision="${VCS_REF}" \
      io.github.shell-echo.sandbox-runtime.role-target="${ROLE_TARGET}" \
      io.github.shell-echo.sandbox-runtime.go-version="go1.26.8"

COPY --chmod=0555 role /usr/local/bin/phase6-role

USER 65532:65532
WORKDIR /
ENTRYPOINT ["/usr/local/bin/phase6-role"]

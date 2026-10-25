#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <linux/amd64|linux/arm64/v8> <role-target> [independent-public-key-file]" >&2
    exit 2
fi

platform=$1
target=$2
case "$platform" in
    linux/amd64) goarch=amd64; platform_token=linux-amd64 ;;
    linux/arm64/v8) goarch=arm64; platform_token=linux-arm64-v8 ;;
    *) echo "unsupported platform" >&2; exit 2 ;;
esac
case "$target" in
    core) package=. ;;
    provider-docker-control-bootstrap-v1|provider-docker-control-delivery-v2|provider-docker-control-source-v3|provider-docker-control-trust-v4) package=./cmd/provider-docker-control ;;
    browser-action-ingress|browser-executor-backend|desktop-executor-backend|certificate-controller|\
    workload-tls-agent|workload-material-agent|workload-credential-controller-v2|\
    break-glass-controller|egress-policy-broker|egress-policy-state-authority|phase6-ingress-relay)
        package=./cmd/$target ;;
    *) echo "unsupported Phase 6 role target" >&2; exit 2 ;;
esac
if [ "$target" = provider-docker-control-delivery-v2 ] || [ "$target" = provider-docker-control-source-v3 ] || [ "$target" = provider-docker-control-trust-v4 ]; then
    [ "$#" -eq 3 ] || { echo "new Control delivery target requires independent public key" >&2; exit 2; }
else
    [ "$#" -eq 2 ] || { echo "pin input is only valid for the new Control delivery target" >&2; exit 2; }
fi
case "$target" in
    provider-docker-control-delivery-v2|provider-docker-control-source-v3|provider-docker-control-trust-v4) stage=control-delivery ;;
    certificate-controller|workload-tls-agent|workload-material-agent|workload-credential-controller-v2|\
    break-glass-controller|egress-policy-state-authority|provider-docker-control-bootstrap-v1) stage=fd-loader ;;
    *) stage=direct ;;
esac

# Same closed compilation environment as phase6rolecandidate. Storage and
# tool-discovery paths remain caller inputs; this is not tool-origin approval.
# Native helpers omit the cross-compilation selectors used for image binaries.
role_go() (
	role_goos=
	role_goarch=
	if [ "$1" = build ]; then role_goos=linux; role_goarch=$goarch; fi
    exec env -i PATH="$PATH" HOME="$HOME" \
        ${TMPDIR+"TMPDIR=$TMPDIR"} ${GOTMPDIR+"GOTMPDIR=$GOTMPDIR"} \
        ${GOCACHE+"GOCACHE=$GOCACHE"} ${GOMODCACHE+"GOMODCACHE=$GOMODCACHE"} \
        ${XDG_CACHE_HOME+"XDG_CACHE_HOME=$XDG_CACHE_HOME"} \
        ${SystemRoot+"SystemRoot=$SystemRoot"} ${SYSTEMROOT+"SYSTEMROOT=$SYSTEMROOT"} \
        ${TEMP+"TEMP=$TEMP"} ${TMP+"TMP=$TMP"} \
        CGO_ENABLED=0 GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS= GOMAXPROCS=2 \
        GO111MODULE=on GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0 \
        GOPROXY=off GOSUMDB=off GOPRIVATE= GONOPROXY=none GONOSUMDB=none GOINSECURE= \
        GOAUTH=off 'GOVCS=*:off' MISE_AUTO_INSTALL=0 LANG=C LC_ALL=C \
        GOOS="$role_goos" GOARCH="$role_goarch" go "$@"
)

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
if [ "$(role_go env GOVERSION)" != "go1.26.8" ]; then
    echo "Phase 6 role candidate requires Go 1.26.8" >&2
    exit 2
fi
if [ -n "$(git -C "$repository_root" status --porcelain --untracked-files=all)" ]; then
    echo "Phase 6 role candidate source must be clean and committed" >&2
    exit 2
fi
source_revision=$(git -C "$repository_root" rev-parse HEAD)
if [ "${#source_revision}" -ne 40 ] || [ -n "$(printf '%s' "$source_revision" | tr -d '0-9a-f')" ]; then
    echo "invalid source revision" >&2
    exit 2
fi
pin=
ldflags=-buildid=
if [ "$target" = provider-docker-control-delivery-v2 ] || [ "$target" = provider-docker-control-source-v3 ] || [ "$target" = provider-docker-control-trust-v4 ]; then
    # Exact public bytes are checked by repository code after the clean-source
    # and toolchain guards. This input is separate from Profile/startup files.
    pin=$(cd "$repository_root" && role_go run -p=2 -mod=readonly ./tools/control-pin "$3")
    ldflags="$ldflags -X github.com/shell-echo/sandbox-runtime/internal/controlbootstrap.publicKeyPin=$pin"
fi
image_tag="sandbox-runtime-phase6-local-${target}:${source_revision}-${platform_token}"
build_context=$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-phase6-role.XXXXXX")
build_context=$(CDPATH= cd -- "$build_context" && pwd -P)
cleanup() { rm -rf -- "$build_context"; }
trap cleanup EXIT HUP INT TERM

(
    cd "$repository_root"
    role_go build -p=2 -mod=readonly -trimpath -buildvcs=false -ldflags="$ldflags" \
        -o "$build_context/role" "$package"
)
chmod 0555 "$build_context/role"
if [ "$stage" = fd-loader ] || [ "$stage" = control-delivery ]; then
    (
        cd "$repository_root"
        role_go build -p=2 -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
            -o "$build_context/loader" ./cmd/phase6-fd-loader
    )
    chmod 0555 "$build_context/loader"
    touch -t 197001010000 "$build_context/loader"
fi
if [ "$stage" = control-delivery ]; then
    (cd "$repository_root" && role_go build -p=2 -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o "$build_context/probe" ./tools/control-process-observe)
    chmod 0555 "$build_context/probe"
    touch -t 197001010000 "$build_context/probe"
fi
cp "$script_dir/Dockerfile" "$build_context/Dockerfile"
touch -t 197001010000 "$build_context/role" "$build_context/Dockerfile"

provenance=false
if [ "$stage" = control-delivery ]; then provenance=mode=min; fi
docker build --no-cache --network none --provenance="$provenance" --pull=false \
    --platform "$platform" --target "$stage" --build-arg "VCS_REF=$source_revision" \
    --build-arg "ROLE_TARGET=$target" --build-arg SOURCE_DATE_EPOCH=0 \
    --tag "$image_tag" "$build_context"

image_digest=$(docker image inspect --format '{{.Id}}' "$image_tag")
image_hex=${image_digest#sha256:}
if [ "$image_digest" = "$image_hex" ] || [ "${#image_hex}" -ne 64 ] ||
    [ -n "$(printf '%s' "$image_hex" | tr -d '0-9a-f')" ]; then
    echo "invalid local candidate image identity" >&2
    exit 2
fi
printf 'candidate=local-only-non-release\nsource=%s\ntarget=%s\nimage=%s\n' \
    "$source_revision" "$target" "$image_digest"

if [ -n "$pin" ]; then printf 'operator_public_key_pin=%s\n' "$pin"; fi

printf 'toolchain=go1.26.8\ngoenv=off\ngowork=off\ngo_mod_blob=%s\ngo_sum_blob=%s\n' \
    "$(git -C "$repository_root" rev-parse "$source_revision:go.mod")" \
    "$(git -C "$repository_root" rev-parse "$source_revision:go.sum")"

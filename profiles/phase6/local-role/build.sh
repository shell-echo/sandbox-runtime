#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <linux/amd64|linux/arm64/v8> <role-target>" >&2
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
    browser-action-ingress|browser-executor-backend|desktop-executor-backend|certificate-controller|\
    workload-tls-agent|workload-material-agent|workload-credential-controller-v2|\
    break-glass-controller|egress-policy-broker|egress-policy-state-authority|phase6-ingress-relay)
        package=./cmd/$target ;;
    *) echo "unsupported Phase 6 role target" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
if [ "$(go env GOVERSION)" != "go1.26.8" ]; then
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
image_tag="sandbox-runtime-phase6-local-${target}:${source_revision}-${platform_token}"
build_context=$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-phase6-role.XXXXXX")
build_context=$(CDPATH= cd -- "$build_context" && pwd -P)
cleanup() { rm -rf -- "$build_context"; }
trap cleanup EXIT HUP INT TERM

(
    cd "$repository_root"
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOPROXY=off GOSUMDB=off \
        GOTOOLCHAIN=local GOFLAGS= \
        go build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
        -o "$build_context/role" "$package"
)
chmod 0555 "$build_context/role"
cp "$script_dir/Dockerfile" "$build_context/Dockerfile"
touch -t 197001010000 "$build_context/role" "$build_context/Dockerfile"

docker build --no-cache --network none --provenance=false --pull=false \
    --platform "$platform" --build-arg "VCS_REF=$source_revision" \
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

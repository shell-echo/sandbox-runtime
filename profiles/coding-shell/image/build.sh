#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <linux/amd64|linux/arm64/v8> <image-tag> [source-revision]" >&2
    exit 2
fi

platform=$1
image_tag=$2
source_revision=${3:-unknown}

case "$platform" in
    linux/amd64)
        goarch=amd64
        base_digest=sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3
        ;;
    linux/arm64/v8)
        goarch=arm64
        base_digest=sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c
        ;;
    *)
        echo "unsupported platform: $platform" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
go_version=$(go env GOVERSION)
if [ "$go_version" != "go1.26.5" ]; then
    echo "unsupported Go toolchain: $go_version (want go1.26.5)" >&2
    exit 2
fi
build_context=$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-coding-shell.XXXXXX")
cleanup() {
    rm -rf -- "$build_context"
}
trap cleanup EXIT HUP INT TERM

(
    cd "$repository_root"
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
        go build -trimpath -buildvcs=false -ldflags=-buildid= \
        -o "$build_context/terminal-broker" ./cmd/terminal-broker
)
chmod 0555 "$build_context/terminal-broker"
touch -t 197001010000 "$build_context/terminal-broker"
cp "$script_dir/Dockerfile" "$build_context/Dockerfile"

docker build \
    --no-cache \
    --provenance=false \
    --platform "$platform" \
    --build-arg "BASE_IMAGE_DIGEST=$base_digest" \
    --build-arg SOURCE_DATE_EPOCH=0 \
    --build-arg "VCS_REF=$source_revision" \
    --tag "$image_tag" \
    "$build_context"

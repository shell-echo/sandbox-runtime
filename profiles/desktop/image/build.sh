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
        archive_digest=872446c241d2c85db9995b1e12ca4246954f76883108f1e16415d8a0e711c4a6
        installed_digest=ea4e22c1f7011c6cfc975d64c5f2d110b3432bc5ae78064b94f7afa752e0a588
        ;;
    linux/arm64/v8)
        goarch=arm64
        base_digest=sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c
        archive_digest=f6a17c5b4031b4068ae345333cdfc3d09a3ef30dfe77a461f13306d3cf5ac656
        installed_digest=25e5d714836bacf2e421a1d586d7c8d64a65887036989cc08810697a6dd8ec31
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
build_context=$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-desktop.XXXXXX")
cleanup() {
    rm -rf -- "$build_context"
}
trap cleanup EXIT HUP INT TERM

(
    cd "$repository_root"
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
        go build -trimpath -buildvcs=false -ldflags=-buildid= \
        -o "$build_context/desktop-broker" ./cmd/desktop-broker
)
chmod 0555 "$build_context/desktop-broker"
touch -t 197001010000 "$build_context/desktop-broker"
cp "$script_dir/Dockerfile" "$build_context/Dockerfile"
cp "$script_dir/entrypoint.sh" "$build_context/entrypoint.sh"
touch -t 197001010000 "$build_context/Dockerfile" "$build_context/entrypoint.sh"

docker build \
    --no-cache \
    --provenance=false \
    --platform "$platform" \
    --build-arg "BASE_IMAGE_DIGEST=$base_digest" \
    --build-arg "PACKAGE_ARCHIVE_SET_SHA256=$archive_digest" \
    --build-arg "INSTALLED_SET_SHA256=$installed_digest" \
    --build-arg SOURCE_DATE_EPOCH=0 \
    --build-arg "VCS_REF=$source_revision" \
    --tag "$image_tag" \
    "$build_context"

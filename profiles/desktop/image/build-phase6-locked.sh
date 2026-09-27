#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <linux/amd64|linux/arm64/v8> <image-tag> <source-revision> <absolute-private-accounts-file>" >&2
    exit 2
fi

platform=$1
image_tag=$2
source_revision=$3
accounts_file=$4
case "$platform" in
    linux/amd64) goarch=amd64; lock=phase6-apk-lock-amd64.json ;;
    linux/arm64/v8) goarch=arm64; lock=phase6-apk-lock-arm64.json ;;
    *) echo "unsupported platform: $platform" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
go_version=$(go env GOVERSION)
if [ "$go_version" != "go1.26.8" ]; then
    echo "unsupported Go toolchain: $go_version (want go1.26.8)" >&2
    exit 2
fi
build_context=$(mktemp -d "${TMPDIR:-/tmp}/sandbox-runtime-desktop-phase6.XXXXXX")
build_context=$(CDPATH= cd -- "$build_context" && pwd -P)
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
cp "$script_dir/Dockerfile.phase6-candidate" "$build_context/Dockerfile"
cp "$script_dir/entrypoint.sh" "$build_context/entrypoint.sh"
touch -t 197001010000 "$build_context/Dockerfile" "$build_context/entrypoint.sh"

accounts_output=$(
    cd "$repository_root"
    go run ./cmd/prepare-desktop-phase6-accounts \
        -allowlist "$accounts_file" -output "$build_context"
)
account_digest=$(printf '%s\n' "$accounts_output" | sed -n 's/^workload_account_digest=//p')
case "$account_digest" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "invalid workload account digest" >&2; exit 2 ;;
esac
touch -t 197001010000 "$build_context/workload-accounts.json" "$build_context/workload.passwd" "$build_context/workload.group"

stage_output=$(
    cd "$repository_root"
    go run ./cmd/stage-desktop-phase6-apks \
        -lock "$script_dir/$lock" -output "$build_context" \
        -cache "${SANDBOX_RUNTIME_DESKTOP_APK_CACHE:-}"
)
archive_digest=$(printf '%s\n' "$stage_output" | sed -n 's/^archive_set_digest=sha256://p')
installed_digest=$(printf '%s\n' "$stage_output" | sed -n 's/^installed_set_digest=sha256://p')
lock_digest=$(printf '%s\n' "$stage_output" | sed -n 's/^lock_digest=sha256://p')
base_digest=$(printf '%s\n' "$stage_output" | sed -n 's/^base_image_digest=//p')
if [ "${#archive_digest}" -ne 64 ] || [ "${#installed_digest}" -ne 64 ] || [ "${#lock_digest}" -ne 64 ]; then
    echo "invalid staged Phase 6 package authority" >&2
    exit 2
fi

# Normalized context timestamps make the verified archive bytes reproducible.
find "$build_context/apks" -type f -exec touch -t 197001010000 {} +
touch -t 197001010000 "$build_context/SHA256SUMS"

docker build \
    --no-cache \
    --network none \
    --provenance=false \
    --platform "$platform" \
    --build-arg "BASE_IMAGE_DIGEST=$base_digest" \
    --build-arg "PACKAGE_ARCHIVE_SET_SHA256=$archive_digest" \
    --build-arg "INSTALLED_SET_SHA256=$installed_digest" \
    --build-arg "APK_LOCK_SHA256=$lock_digest" \
    --build-arg "WORKLOAD_ACCOUNT_DIGEST=$account_digest" \
    --build-arg SOURCE_DATE_EPOCH=0 \
    --build-arg "VCS_REF=$source_revision" \
    --tag "$image_tag" \
    "$build_context"

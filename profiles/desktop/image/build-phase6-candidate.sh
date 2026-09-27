#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <linux/amd64|linux/arm64/v8> <absolute-candidate-manifest-path> <absolute-private-accounts-file>" >&2
    exit 2
fi

platform=$1
output=$2
accounts_file=$3
case "$output" in
    /*) ;;
    *) echo "candidate manifest path must be absolute" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
if [ -n "$(git -C "$repository_root" status --porcelain --untracked-files=all)" ]; then
    echo "Phase 6 candidate source tree must be clean and committed" >&2
    exit 2
fi
source_revision=$(git -C "$repository_root" rev-parse HEAD)
platform_token=$(printf '%s' "$platform" | tr '/:' '--')
image_tag="sandbox-runtime-desktop-phase6-candidate:${source_revision}-${platform_token}"

"$script_dir/build-phase6-locked.sh" "$platform" "$image_tag" "$source_revision" "$accounts_file"

(
    cd "$repository_root"
    go run ./cmd/record-desktop-phase6-candidate \
        -source-root "$repository_root" \
        -platform "$platform" \
        -image "$image_tag" \
        -accounts-file "$accounts_file" \
        -output "$output"
)

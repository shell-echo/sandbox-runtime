#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
    printf '%s\n' 'Desktop runtime does not accept command-line overrides' >&2
    exit 64
fi

exec /usr/local/libexec/sandbox-runtime/desktop-broker serve

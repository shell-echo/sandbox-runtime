#!/bin/sh
set -eu

# The current headless-shell build has no usable Chromium sandbox when Docker
# user namespaces are unavailable. Keep this development-only escape hatch
# explicit and fail closed for every default or production-like invocation.
if [ "${BROWSER_RUNTIME_ALLOW_UNSANDBOXED:-0}" != "1" ]; then
	printf '%s\n' 'browser runtime requires BROWSER_RUNTIME_ALLOW_UNSANDBOXED=1 for development smoke tests' >&2
	exit 78
fi

if [ "$#" -ne 0 ]; then
	printf '%s\n' 'browser runtime does not accept command-line overrides' >&2
	exit 64
fi

mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"

exec /headless-shell/headless-shell \
	--headless \
	--no-sandbox \
	--disable-gpu \
	--disable-dev-shm-usage \
	--no-first-run \
	--no-default-browser-check \
	--user-data-dir="$XDG_CACHE_HOME/profile" \
	--remote-debugging-address=127.0.0.1 \
	--remote-debugging-port=9222

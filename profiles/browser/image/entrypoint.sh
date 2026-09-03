#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
	printf '%s\n' 'browser runtime does not accept command-line overrides' >&2
	exit 64
fi

mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"

exec /headless-shell/headless-shell \
	--headless \
	--disable-gpu \
	--disable-dev-shm-usage \
	--no-first-run \
	--no-default-browser-check \
	--user-data-dir="$XDG_CACHE_HOME/profile" \
	--remote-debugging-address=127.0.0.1 \
	--remote-debugging-port=9222

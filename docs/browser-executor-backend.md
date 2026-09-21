# Browser Executor Backend

`cmd/browser-executor-backend` is the operator-owned private relay for the
independent Browser role. It is a separate process from both Provider and the
Browser executor role.

The backend owns only:

- a pinned Chromium CDP WebSocket URL supplied by the operator;
- its own server certificate, private key, client CA, and URI identity allowlist;
- a bounded concurrent-session policy.

It does not read Provider state, write PostgreSQL, resolve handoff references,
or access Docker. The Browser role sends a complete `sandbox-runtime.executor.v2`
authority over mTLS. The backend rejects malformed, expired, role-mismatched,
digest-mismatched, and replayed authorities before opening the CDP upstream.

The authority document is a mode-0600 private regular file. A minimal shape is:

```json
{
  "version": 1,
  "role": "browser",
  "listen_address": "127.0.0.1:9443",
  "upstream_url": "ws://127.0.0.1:9222/devtools/browser/<opaque-id>",
  "server_certificate_file": "/run/private/browser-executor/server.pem",
  "server_private_key_file": "/run/private/browser-executor/server.key",
  "client_ca_bundle_file": "/run/private/browser-executor/ca.pem",
  "allowed_client_identities": ["spiffe://sandbox-runtime/browser-role"],
  "max_sessions": 32,
  "operation_timeout_millis": 5000
}
```

Start it independently:

```bash
go run ./cmd/browser-executor-backend serve /absolute/path/to/authority.json
```

The `upstream_url` must identify the private CDP endpoint of the already
started pinned Browser runtime. The relay does not start that runtime and does
not publish its loopback endpoint. For the repository's real-CDP check, start
the locked Browser image, obtain its `/json/version` WebSocket URL, configure
the authority, and run:

```bash
SANDBOX_RUNTIME_EXECUTOR_BACKEND_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_CDP_URL='ws://127.0.0.1:.../devtools/browser/...' \
go test -tags=integration -run '^TestBrowserBackendRealCDP$' -count=1 \
  ./internal/executorbackend
```

This is local component/process evidence only. It does not establish a
published deployment, certificate issuance, operator acceptance, or Phase 6
release readiness.

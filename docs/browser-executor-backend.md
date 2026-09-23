# Browser Executor Backend

`cmd/browser-executor-backend` is the operator-owned private relay for the
independent Browser role. It is a separate process from both Provider and the
Browser executor role.

The backend owns only:

- a pinned Chromium CDP WebSocket URL supplied by the operator;
- a profile-bound TLS-agent signer socket, pinned server/client CA bundles,
  and the sole Browser-role client identity declared by the security profile;
- a bounded concurrent-session policy.

It does not read Provider state, write PostgreSQL, resolve handoff references,
or access Docker. The Browser role sends a complete `sandbox-runtime.executor.v2`
authority over mTLS. The backend rejects malformed, expired, role-mismatched,
digest-mismatched, and replayed authorities before opening the CDP upstream.

The authority document is a mode-0600 private regular file. A minimal shape is:

```json
{
  "version": 2,
  "role": "browser",
  "listen_address": "127.0.0.1:9443",
  "upstream_url": "ws://127.0.0.1:9222/devtools/browser/<opaque-id>",
  "security_profile_path": "/run/private/phase6-security-profile.json",
  "security_profile_digest": "sha256:<64 lowercase hex digits>",
  "tls_agent_socket": "/run/tls/browser-executor-tls-agent/signer.sock",
  "tls_agent_uid": 20001,
  "tls_agent_gid": 30001,
  "max_sessions": 32,
  "operation_timeout_millis": 5000
}
```

Start it independently:

```bash
go run ./cmd/browser-executor-backend serve /absolute/path/to/authority.json
```

The profile supplies the read-only server/client CA artifacts, exact SHA-256
digests, mount identities and permitted consumers. The UID/GID and port above
are illustrative; production values must match the
verified profile and the actual process identity. Version 1 local-key
authority is not accepted by the production command. Every new TLS handshake
obtains a validated certificate from the agent; signer loss denies new
handshakes. Existing connection revocation/drain still requires its named
gate.

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

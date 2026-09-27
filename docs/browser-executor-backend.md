# Browser Executor Backend

`cmd/browser-executor-backend` is the operator-owned private relay for the
independent Browser role. It is a separate process from both Provider and the
Browser executor role.

The backend owns only:

- a restricted Unix socket to the Provider-owned typed Browser allocation mux;
- a profile-bound TLS-agent signer socket, pinned server/client CA bundles,
  and the sole Browser-role client identity declared by the security profile;
- a bounded concurrent-session policy.

It does not read Provider state, write PostgreSQL, resolve handoff references,
or access Docker. The Browser role sends a complete `sandbox-runtime.executor.v2`
authority over mTLS. The backend rejects malformed, expired, role-mismatched,
digest-mismatched, and replayed authorities before asking the mux for the
current Provider-selected allocation. It cannot choose a URL or container.

The authority document is a mode-0600 private regular file. A minimal shape is:

```json
{
  "version": 3,
  "role": "browser",
  "listen_address": "127.0.0.1:9443",
  "upstream_url": "",
  "mux_socket_path": "/run/private/browser-mux-<32 lowercase hex>.sock",
  "mux_directory_mode": 456,
  "mux_socket_mode": 438,
  "mux_owner_uid": 20002,
  "mux_directory_gid": 30002,
  "security_profile_path": "/run/private/phase6-security-profile.json",
  "security_profile_digest": "sha256:<64 lowercase hex digits>",
  "peer_crl_role_file": "/run/private/browser-peer-crl-role.json",
  "peer_crl_role_digest": "sha256:<64 lowercase hex digits>",
  "peer_crl_source_mapping_digest": "sha256:<64 lowercase hex digits>",
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
verified profile and the actual process identity. The example socket modes
are decimal encodings of `0710` and `0666`; the restricted parent group and
an exact Unix peer UID check together constrain access. Version 1 local-key
and version 2 fixed-upstream authorities are not accepted by the production
command. Every new TLS handshake
obtains a validated certificate from the agent; signer loss denies new
handshakes. Existing connection revocation/drain still requires its named
gate.

The legacy static-upstream constructor remains a component test path only; it
does not prove Provider allocation-to-target binding. Its historical real-CDP
test starts a locked Browser image, obtains `/json/version`, and runs:

```bash
SANDBOX_RUNTIME_EXECUTOR_BACKEND_INTEGRATION=1 \
SANDBOX_RUNTIME_BROWSER_CDP_URL='ws://127.0.0.1:.../devtools/browser/...' \
go test -tags=integration -run '^TestBrowserBackendRealCDP$' -count=1 \
  ./internal/executorbackend
```

The typed mux and Browser v3 Provider composition still require a real
session→allocation→CDP target, two-session/cross-tenant, restart, revocation,
and exact cleanup gate. This is local component/process evidence only. It does not establish a
published deployment, certificate issuance, operator acceptance, or Phase 6
release readiness.

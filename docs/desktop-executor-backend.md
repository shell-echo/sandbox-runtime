# Desktop Executor Backend

`desktop-executor-backend` is an operator-owned process between the Provider's
Desktop executor role and one pinned Desktop guest broker. It terminates TLS
1.3/mTLS, accepts only `sandbox-runtime.executor.v2`, and relays the signed
Provider bridge statement without recalculating or signing authority.

The backend connects only to a Provider-owned, mode-0600 Unix socket named
`desktop-broker-<32 lowercase hex>.sock` inside an absolute, same-owner,
mode-0700 private runtime directory. It does not open the Provider database or
Docker daemon. The Provider mux revalidates current durable handoff and owned
candidate state, then uses a fixed broker exec. The in-container broker verifies
the Provider Ed25519 key, bridge digest, policy, expiry, generation, fence,
epoch, and one-use nonce on the isolated
`sandbox.runtime/desktop-session.v2` route.

The authority file is a closed JSON document:

```json
{
  "version": 1,
  "role": "desktop",
  "listen_address": "127.0.0.1:8447",
  "broker_socket_path": "/run/user/1000/sandbox-runtime/provider-a1b2/desktop-broker-11111111111111111111111111111111.sock",
  "executor_identity": "executor-desktop-1",
  "server_certificate_file": "/run/private/desktop-backend.crt",
  "server_private_key_file": "/run/private/desktop-backend.key",
  "client_ca_bundle_file": "/run/private/executor-ca.pem",
  "allowed_client_identities": ["spiffe://sandbox-runtime/provider"],
  "max_sessions": 16,
  "operation_timeout_millis": 5000
}
```

The candidate broker's pinned public key is supplied to the broker process through its
operator-owned runtime authority (`SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY`
and `SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID`) together with the explicit
`SANDBOX_RUNTIME_DESKTOP_SESSION_PROTOCOL=sandbox.runtime/desktop-session.v2`
selection. Missing or malformed key material and implicit protocol selection
leave the v2 route unavailable; it never falls back to v1. The mTLS `/readyz`
route succeeds only after the Provider mux mints a fresh signed `probe.v2` from
a previously verified, still-current candidate allocation and proxies it
through the real container broker. Before such an allocation exists, readiness
stays unavailable.

Accepted v2 statements are committed to the bounded broker-local replay ledger
before a session starts. The ledger is private, canonical, atomically replaced,
survives broker process restart, and fails closed on corruption, persistence
failure, expiry, or capacity exhaustion.

An `ok` input result is an injection-layer acknowledgement only: the broker
validated the policy-bound input and the fixed-argument `xdotool` process
completed within its one-second deadline. It does not claim that a visual
change was observed or that an application consumed the event. Repeating a
pointer move at the current coordinates is valid and must complete without
waiting for another pointer movement; cancellation, deadline expiry, or a
nonzero tool exit remains the fixed `input_rejected` result.

# ADR 0034: Browser Action-History Restore Witness

- Status: Accepted for the P4 Browser deleted-history and restored-snapshot
  detection component slice
- Date: 2026-09-06

## Context

ADR 0033 retains one per-session action high-water key until no activated claim
can remain valid. Its action script detects malformed history and a capacity
counter behind retained state, but a missing high-water key is also the normal
shape of a first activation. The component therefore cannot distinguish a
virgin session from an administrator deleting one live key or restoring a
snapshot taken before that session's activation.

Adding another marker to the same Redis-compatible snapshot domain is not a
restore witness. A complete rollback can restore the marker, high-water state,
capacity fence, and policy together. A checksum or hash chain stored only in
that same snapshot has the same limitation. Redis replication offsets, process
memory, server run IDs, and local wall clocks are also not durable independent
history authorities.

Redis serializes a Lua script, but it does not roll back writes already made by
the script when a later Redis command fails. Updating a session record, an
index, and a checkpoint with separate commands can therefore leave a partial
state on an out-of-memory or wrong-type failure. The next design must retain the
single-record discipline established by ADR 0031.

The current ADR 0033 implementation and its E2E lock identify the v1 action
policy and scripts exactly. Rewriting that policy in place would invalidate the
recorded evidence and could turn a missing new control into a permissive
migration. The stronger behavior needs a new policy identity and a new,
explicitly provisioned namespace.

## Decision

Add an explicitly selected witnessed v2 action fencer. Keep the ADR 0033 v1
constructor, scripts, descriptor, and historical caller evidence unchanged.
The v2 fencer is a component until a later caller slice supplies and locks its
deployment configuration; no Provider route, Contract resource, capability,
production advertisement, or default composition changes.

### One bounded action-state record

One Redis hash owns all mutable v2 action history for a capacity namespace. It
contains eight fixed checkpoint fields plus at most 4,096 fields named only by
the SHA-256 fingerprint of an exact Browser session. Each session value retains
the exact opaque capacity member, bound expiry, action subject fingerprint, and
greatest required retention deadline. Raw tenant, sandbox, Browser-session,
grant, handoff, endpoint, credential, or CDP values are not field names or
values.

Session fields do not expire individually. An expired entry remains a
non-sensitive virgin-state marker and may be replaced only by a higher exact
capacity fence. The fixed `history_count` must equal the hash cardinality after
subtracting the eight fixed fields. Verification and authorization scan every
bounded field and require the exact fixed names plus canonical fingerprint-only
session names and values; the history count cannot exceed the checkpoint
sequence. Deleting one session field, replacing it with an unknown equal-count
field, corrupting a retained value, or deleting the complete state hash
therefore fails closed rather than becoming a first activation. The bounded
lifetime cardinality is deliberate: reaching 4,096 distinct Browser sessions
makes new-session activation unavailable and requires a new namespace after the
old namespace is drained. It is not production sizing guidance.

The action script validates policy, exact capacity ownership, checkpoint,
history count, subject, retention, and action window before mutation. A first
or higher-fence activation updates the session value and every mutable
checkpoint field with one multi-field `HSET`. No earlier Redis mutation is
allowed in that decision. A Redis command error or ambiguous result is not an
admitted action.

The immutable v2 policy pins the capacity-policy fingerprint, v2 action and
provision script hashes, checkpoint format, claim and action bounds, and
history cardinality. Provisioning refuses the v1 policy and does not upgrade,
delete, or recreate it.

### Independent monotonic witness

The checkpoint contains a monotonically increasing sequence, a random 256-bit
token, the immediately previous sequence and token, the history count, and the
greatest capacity fence observed by a successful activation. A separate
`ActionHistoryWitness` stores the current sequence and token outside the
Redis-compatible authority's snapshot and restore domain.

Runtime verification and every action load the witness and require the Redis
checkpoint to match it. A Redis checkpoint behind, more than one step ahead, or
divergent from the witness is unavailable. A complete Redis snapshot restored
to an earlier action state is therefore rejected even if its action policy,
capacity counter, and session history are internally well formed.

For an activation:

1. load and validate the independent witness;
2. atomically require its current sequence/token in Redis while installing the
   session state and one newly generated next checkpoint;
3. durably compare-and-swap the independent witness to that exact next
   checkpoint; and
4. report the action admitted only after reloading and confirming the witness.

Concurrent activations serialize through the Redis checkpoint. A contender
reloads the witness and retries a bounded number of times; it does not invent a
successful action after exhaustion.

An interruption can leave Redis exactly one step ahead of the witness. That
state means the session was conservatively fenced but no action was reported
admitted. Verification may advance the witness only when the Redis checkpoint
names the witness's exact sequence/token as its immediate predecessor and the
complete bounded state remains valid. This recovery can only reject more old
work; it cannot resurrect a lower fence. Any other mismatch requires
quarantine or administrative repair outside the runtime path.

### File witness boundary

The component includes a single-process file witness for Darwin and Linux. It
holds a non-blocking lifetime lock, accepts one exact policy fingerprint,
strictly decodes one bounded versioned JSON document, rejects symlinks,
non-regular or non-`0600` state, unknown or duplicate fields, and invalid
checkpoints, and persists compare-and-swap with a synced `0600` temporary file,
atomic rename, and directory sync. Context cancellation is preserved.

The file is independent only when deployment places it on a durability and
restore domain that is not included in Redis/Valkey backup, restore, replica
promotion, or volume rollback. Co-locating both stores, snapshotting both
together, restoring both to the same older checkpoint, copying the file to
multiple ingress processes, or treating an ordinary host filesystem as a
production monotonic service invalidates the guarantee. The adapter is local
component and recovery evidence, not HA or production storage.

Provisioning first performs a mutation-free Redis preflight that requires a
virgin action policy/state, then creates the witness before installing the
matching Redis v2 policy/state. A rejected v1 or non-virgin preflight does not
bind an empty witness to the wrong policy. Runtime startup is verify-only. A
missing or mismatched witness, missing action policy/state, malformed
checkpoint, or v1 namespace fails closed. Neither runtime verification nor
action admission recreates missing authority.

### Restore and operations boundary

This decision detects a retained Redis action state restored behind an
independently retained witness. It does not make arbitrary online restore safe.
An operator must stop or quarantine the unique ingress before replacing the
authoritative Redis state, retain the independent witness, verify the restored
state against it, and resume only after exact verification. If the witness is
missing, has an uncertain durability result, or may have been restored with the
Redis snapshot, the namespace remains unavailable and must be drained or
replaced through a separately reviewed procedure.

The Redis-compatible authority and its administrative write path remain
trusted. The checkpoint token is an opaque continuity value, not a MAC over the
complete action-state hash. A writer that can read the token and rewrite the
hash, count, and retained entries into a different internally consistent state
under the same checkpoint can evade this control. ACL separation, restricted
administrative repair, and tamper-resistant state authentication remain later
deployment and threat-model work.

An action linearized before a restore or outage may already have reached
Chromium and cannot be undone. The unique ingress still owns complete-message
ordering from ADR 0033. This ADR adds history loss and rollback detection; it
does not add CDP exactly-once execution, restore transactions across Chromium,
or a public administrative repair endpoint.

## Release Boundary

The component gate requires focused race/shuffle and real pinned
Redis-compatible tests for:

- strict checkpoint construction, redaction, monotonic compare-and-swap,
  cancellation, file reconstruction, exclusive locking, permissions, symlink,
  unknown/duplicate/trailing JSON, and corrupt state rejection;
- missing or typed-nil witnesses, explicit provision versus verify-only
  startup, immutable v2 policy/descriptor identity, and refusal to rewrite a
  v1 namespace;
- concurrent first activation with exactly one checkpoint advance, same-fence
  idempotency, higher-fence replacement, lower-fence rejection, and action
  subject drift;
- deletion of one retained session field, deletion of the complete action-state
  hash, equal-cardinality replacement with an unknown field, wrong counts,
  extra fields, malformed retained entries or checkpoints, and bounded stable
  errors without raw state;
- an internally consistent pre-activation Redis state restored after the
  witness advanced, including reuse of the same numerical capacity fence, with
  rejection before action admission;
- recovery when Redis committed exactly one valid next checkpoint but witness
  advancement was interrupted, while every other mismatch remains
  unavailable; and
- absence of raw subjects, claims, witness tokens, Redis keys, backend details,
  endpoints, credentials, and CDP payloads from stable errors, descriptors,
  logs, audit, and caller evidence.

Passing the component gate does not switch the downstream reference stack to
v2 or close a caller gate. A later locked multi-process gate must use a clean
v2 namespace and independently durable witness, exercise real Chromium through
the unique ingress, delete retained state, restore a controlled older Redis
snapshot, reconstruct the ingress and witness adapter, prove no upstream dial
or old action, and sanitize all evidence. The test control used to restore
state must remain inaccessible to public Gateways and callers.

Full repository race/shuffle, vet, Contract verification, and the unchanged
locked 48-case Suite remain regression gates. The Contract Suite is not
exercised by the new Browser reliability profile unless a runner actually
invokes it.

This ADR does not establish a production monotonic witness, Redis or Valkey
provenance, persistence configuration, HA/failover consistency, a correlated
two-store restore guarantee, protection from a trusted Redis writer coherently
rewriting state under the current checkpoint, ACL role isolation, ingress
suspension safety, Provider multi-controller reliability, hostile multi-tenant
isolation, real Agent Platform compatibility, aggregate conformance, production
advertisement, deployment readiness, or production readiness.

## Consequences

- A missing retained session field is no longer silently equivalent to a
  virgin session in the v2 namespace.
- A complete Redis action-state rollback is detectable while the independent
  witness retains the later checkpoint.
- Session history and checkpoint move in one Redis command, avoiding a
  multi-key partial-write claim that Redis Lua cannot provide.
- The witness adds a durable compare-and-swap to every first or higher-fence
  activation and a witness read plus an O(n), at-most-4,096-entry Redis history
  validation to every action and verification. Latency, filesystem durability,
  script execution time, and contention require measurement before deployment.
- Permanent fingerprint-only session fields trade bounded namespace capacity
  for deletion detection. Namespace rotation must drain old claims and must not
  be presented as transparent in-place policy migration.
- Correlated rollback of Redis and its supposed witness remains undetectable;
  operational independence is part of the safety property, not an optional
  deployment detail.

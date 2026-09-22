# Product Phase 6 Recording Key-Handle Migration

Date: 2026-09-22

Status: pre-production migration contract; no production migration has been
executed or claimed.

## Boundary

The production KMS recording store accepts only canonical `rkms1:` key handles
and `sandbox-runtime.recording-segment.v1` encrypted segment documents. The
development local store accepts only tenant/recording-bound `rkey2:` handles.
Legacy `rkey:` handles are rejected. Neither store falls back to another
format, and normal reads never rewrite durable state.

Before enabling the KMS store, an operator must establish exactly one of these
preconditions:

1. the target production catalog contains no legacy recording rows or segment
   objects; or
2. an approved offline migration has completed and its immutable report proves
   exact source/target counts and integrity.

## Offline migration requirements

An offline migration must stop recording creation, append and replay for the
affected tenant scope, take a catalog and content backup, and pin the source
format, target format, KMS binding digest and active KMS version. It must use
authenticated tenant and recording identities from the catalog; a persisted
handle is never authority by itself.

For each recording, the migration must decrypt every legacy segment through
the old development authority, create one new random recording DEK, wrap that
DEK with the configured KMS version, encrypt every segment with the canonical
target AAD, and verify a full target replay before changing the catalog handle.
The report must contain only non-secret digests and counts. It must not contain
plaintext, local master keys, Vault tokens, KMS references/endpoints, wrapped
DEKs, host paths or backend diagnostics.

The catalog switch is permitted only after all target objects are durable and
verified. Source objects remain read-disabled and retained only for the
approved rollback window. After the window, deletion must be separately
authorized and must prove exact source-object cleanup. A partially migrated
recording remains unavailable; runtime dual-read and best-effort repair are
forbidden.

## Rollback limit

Rollback means restoring the pre-migration catalog and source objects while
the approved source-retention window is still open. New recordings written in
the target format cannot be converted back by the runtime. Once source objects
or their legacy key authority have been destroyed, rollback is impossible and
must fail closed.

## Required evidence

The final migration tool and run must prove cancellation, restart/resume,
duplicate invocation, cross-tenant substitution denial, corrupt source/target
rejection, KMS loss, catalog-switch atomicity, plaintext exclusion and exact
cleanup. This document does not claim that such a tool or run already exists.

# PostgreSQL Action-History Witness

Apply `0001_action_history_witness.sql` with a migration owner before starting
the witnessed-v2 runtime. Runtime startup never creates or alters this schema.

Grant the runtime role only the permissions needed by `Load`, `Provision`, and
`CompareAndSwap`:

```sql
GRANT CONNECT ON DATABASE your_database TO sandbox_runtime_witness;
GRANT USAGE ON SCHEMA sandbox_runtime TO sandbox_runtime_witness;
GRANT SELECT ON TABLE sandbox_runtime.action_history_witnesses
    TO sandbox_runtime_witness;
GRANT INSERT (namespace_fingerprint, policy_fingerprint, format_version, sequence, token)
    ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness;
GRANT UPDATE (sequence, token, updated_at)
    ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness;
```

The runtime role must not own the database, schema, or table and must not have
`CREATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, or role-management
privileges. Keep the migration credential out of the Gateway and ingress.

Deploy this database in a failure, backup, snapshot, restore, and access-control
domain independent from the Redis-compatible capacity authority. A correlated
rollback of both stores is not detectable. Do not run a restore check until the
unique private ingress is quarantined, and do not resume it unless
`VerifyRestoredState` succeeds against the retained witness.

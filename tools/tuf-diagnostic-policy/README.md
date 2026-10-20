# Fixed Cosign diagnostic capture policy

This dependency-free Python module checks the **syntax and natural capture**
of the frozen Cosign 3.1.3 four-case diagnostic. It does not run Cosign, access
the network, read a cache, verify TUF signatures, or supply runtime admission.
There is no command that reports a cryptographic pass.

`warnings_and_error` accepts exactly two fixed modern-client file warnings for
`good`; each negative requires those warnings plus `Error: P` and the
untimestamped final `error during command execution: P`. Both complete payloads
must equal the fixed case payload. The two warnings have different wrappers.
The target payload includes the complete expected and actual SHA256 from the
frozen target inputs. Matching uses exact UTF8/LF bytes including the final LF,
without stripping, URL normalization, substrings or alternate line formats.

`validate_capture` additionally requires the original natural exit, reviewed
argv, 25-second/1-MiB limits, strict receipt types, full stream byte counts,
no signals/truncation/timeout and empty negative stdout. A caller must obtain
`expected_argv` from its independently reviewed source/input lock; this module
does not authenticate the receipt or its producer. Results explicitly remain
format-only and unauthenticated.

The private caller must still bind the exact binary and complete inputs,
collect target-absence facts before parsing (including broken symlinks and
unknown errors), enforce state identity and all postchecks, authenticate good's
full Root status/roles/target bytes, preserve original host/supply/isolation
gates and case order, and keep every negative provisional until the unchanged
good and the whole batch pass independent actual review. A historical stderr
may test parsing only; it cannot retroactively change a failed run. A new
candidate requires its own reviewed input identity, not edited historical locks.

Run component tests using the already installed mise Python, without global
activation or installation:

```sh
mise exec python@3.13.16 -- python -B -m unittest discover -s tools/tuf-diagnostic-policy -v
```

These independent synthetic literals and refusal cases are not TUF execution
or release evidence. The private adapter/runner, original receipts and caches
are intentionally outside Git; only this reusable policy and synthetic tests
are versioned here. The source rationale is recorded in the
[Phase 6 checkpoint](../../docs/plan/product-v1-phase-6-vault-generator-output.md#2026-10-20-util-and-standard-log-source-correspondence).

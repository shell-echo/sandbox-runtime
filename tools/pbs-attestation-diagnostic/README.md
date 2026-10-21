# Fixed PBS attestation diagnostic components

These dependency-free Python components implement the reviewed eight-case
Cosign 3.1.3 diagnostic policy. They do not change Cosign, Provider behavior,
repository toolchains, release locks or evidence reuse rules.

Run the synthetic component tests with the existing managed Python, without
installing packages or changing the shell:

```sh
mise exec python@3.13.16 -- python -B -m unittest discover -s tools/pbs-attestation-diagnostic -p 'test_*.py' -v
```

`policy.py` rejects duplicate/nonfinite/oversized JSON and noncanonical base64,
checks the complete original bundle and all subjects, and matches complete
finite output frames against natural bounded receipts. Good results re-read
the same pinned original bundle, rather than treating CLI text or reserialized
JSON as the signed statement. Both selected digests share one publisher
statement. Negative DSSE mutation may fail the Rekor binding first.

`files.py` uses complete no-follow reads, EOF and file/parent identity checks.
`capture.py` preserves raw streams and failure facts. An owned outer capture
must place the batch in its own process group, enforce 90 seconds over the
entire batch, and kill that group on timeout/capture failure. Leaves inherit
the group and retain the original 25-second/1-MiB bounds. A failed controller
preserves its final report and kills its entire owned group, including itself;
the outer capture retains and reaps that signalled failure. Successful leaf and
batch closure require a concrete, source-bound current group census containing
only the batch controller. That native observer and race handling remain a
separately reviewed private prerequisite; the component has no boolean fallback
and does not yet prove successful process-tree closure. Cleanup elapsed time
is recorded and cannot turn a timeout into a pass. Synthetic process-tree
fixtures test supervision; they are not extra verification workers.
Leaves inherit their caller's working directory. The concrete private outer
must select and bind an exclusive private cwd before execution; the minimal
environment alone does not establish cwd isolation.

`controller.py` is a library, deliberately without a runnable admission CLI.
A separately reviewed private wrapper and guard implementation must bind the
complete source/tool/supplier/TUF/input graph, nine tool aliases, original
fresh dual-host evidence, same daemon/boot and deny-network proof. A boolean
guard or a source-design approval is insufficient. Its explicit review record
must bind the concrete plan and closed error frames before an attempt; the
outer caller pins that review by value. The library cannot establish human
review authority. Every case checks complete inputs and guards before/after,
retains full bounded state, refuses unexpected caches, and never emits
cryptographic or product acceptance. Actual results need independent joint
review with both unchanged good cases.

`der_metadata.py` only reads bounded certificate extension bytes. It does not
check signatures, CA, certificate validity, SCT, revocation or Sigstore summary
semantics. Its SAN/issuer strings are candidate frame inputs. At this checkpoint
the retained source graph still lacks the concrete certificate-summary and
Rekor-entry extraction edges. All eight frames are conditional candidates,
and real execution is **HELD** until those edges, the private outer/guards,
complete new inputs and current metadata are independently closed. Do not
replace an unknown real error with a candidate or relax an assertion to run.

Synthetic tests and an unexecuted prepared identity are component evidence
only. No host/Cosign cases, archive/SDK recovery, native build or scan follow
automatically. GOMAXPROCS=2 does not prove a host CPU/memory quota. Existing
Docker quotas, 9 bindings, 64 barriers, old evidence and disabled timers remain.

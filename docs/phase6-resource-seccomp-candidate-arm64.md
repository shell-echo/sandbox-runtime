# Phase 6 arm64 resource/seccomp candidate

Status: source-bound **candidate input only**, not an approved deployment policy,
host-admission result, least-privilege proof, or Slice 6 release evidence. The
exact machine-readable table is
[`policy-arm64.json`](../profiles/phase6/security/policy-arm64.json). It covers
23 duties, 82 deployment identities and five external services. Its loader
checks complete membership, canonical bytes, original/applied source digests,
licenses and finite arithmetic. It does not observe Docker application.

## Policy families and open reviews

- Seven control/key/material duties (`break_glass_controller`,
  `certificate_controller`, `credential_controller`,
  `egress_policy_authority`, `migration_material_agent`,
  `runtime_material_agent`, `tls_agent`) use the applied
  [`go-controller-agent-seccomp-arm64.json`](../profiles/phase6/security/go-controller-agent-seccomp-arm64.json),
  SHA-256 `a7f79239f02d9326e74deb212d2022f4bb2db9e2316367e0d89c9e35f7893eaa`.
  It derives from the retained Moby default at commit
  `836ae4d37ef2ec995c77c99fc55f5b5f3af3a897`, whose original JSON is
  SHA-256 `536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`.
  The exact delta removes the unconditional `minKernel=4.8` allowance for
  `ptrace`, `process_vm_readv`, `process_vm_writev`, and the entire conditional
  `CAP_SYS_PTRACE` process-inspection branch (`kcmp`, `pidfd_getfd`,
  `process_madvise` and those same three calls). These duties have no
  process-inspection function. Ordinary thread creation, I/O and the Moby
  `clone3` ENOSYS fallback remain. The other Moby rules, including
  capability/argument-conditioned rules, still require an applied-condition
  review; neither cap-drop alone nor this static diff proves every syscall is
  denied. Real controller/agent startup, rotation, revocation, negative probes
  and exact cgroup observations remain open.
- `chromium_sandbox` uses the pre-existing Browser-only Playwright-derived
  policy, SHA-256
  `3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b`.
  Its arm64 high-UID/CDP/chroot A/B component observation is recorded in the
  [Slice 6 startup audit](audits/product-phase-6-slice-6-startup.md). It is not
  an exception transferable to a Go service or Desktop.
- The other 15 duties currently name the retained **unchanged Moby baseline**
  as a provisional component-calibration input. This is explicitly *not*
  acceptance that their syscall needs are equivalent or least privilege. In
  particular, its kernel-version-conditioned process-inspection branch is
  not blocked by `CAP_SYS_PTRACE` removal. Before final admission, review by
  actual behavior family (pure Go network/file, execution/materialization,
  Desktop multi-process media), derive a narrower policy wherever a sensitive
  allowance has no duty purpose, and run representative positive/negative
  probes. Every deployment still needs its own applied-policy observation.

The retained original Moby JSON and Apache-2.0 license are under
[`profiles/phase6/security/originals`](../profiles/phase6/security/originals/NOTICE.moby-default-seccomp).
The Playwright original, applied Browser bytes and license have distinct
digests in the manifest. An upstream source URL and a local digest do not
establish publication authenticity or running-container enforcement.

An opt-in real arm64 Docker A/B *component probe* now compares these exact
Moby and derived bytes. Both variants ran the same built self-memory probe in
the pinned Alpine fixture with UID/GID 59001:59011, no network, read-only
root, cap-drop-all, no-new-privileges, 64 MiB, 50m CPU and 16 PIDs. Docker's
inspected normalized applied JSON matched each source. The process reported
zero effective capabilities, NNP=1 and seccomp mode 2. Under original Moby,
`process_vm_readv` and `process_vm_writev` each transferred six bytes from/to
its own memory and `PTRACE_TRACEME` succeeded; under the derivative all three
returned EPERM. The same target,
identity and constraints across A/B make this a policy-delta observation,
not an EPERM-only attribution. Both exact-name containers and the private
probe directory were removed. This does **not** exercise a real
credential/certificate controller or agent, other sensitive syscalls, or
deadline/resource behavior. The tagged test is
`TestPhase6ControllerAgentSeccompDeltaRealDocker` in
[`resource_seccomp_integration_test.go`](../internal/phase6profilebuilder/resource_seccomp_integration_test.go).

The existing opt-in
[`TestCredentialV2CrossUIDDocker`](../internal/workloadcredentialv2/unix_docker_integration_test.go)
also now applies these exact derived bytes to its separate high-UID issuer
and client helpers. It passed normal issue/renew/status/revoke, wrong-peer,
wrong-GID, missing/half-frame, cancel, substituted socket and close tests.
The issuer ran under the candidate `credential_controller` 128 MiB/200m/32
PIDs, and clients under `runtime_material_agent` 96 MiB/100m/32 PIDs. Its
running issuer reported the expected cgroup maxima, seccomp mode 2, zero
effective capabilities and NNP=1; a sample recorded 13,012,992-byte memory
peak, 10 PID peak, zero OOM/OOM-kill and CPU throttling 2/66 periods
(45,736 microseconds). The two named server/attack containers, volume and
build directory were checked absent; transient `--rm` clients were not
separately inventoried. This exercises real Unix transport code with a **fake
credential backend** and test binary, not Vault, production controller
startup, renewal pressure or ten-second revocation timing.

## Initial finite limits, not measured tiers

The table gives memory MiB / CPU millicores / PIDs per *deployment* in each
duty. Values are initial assumptions to test, not claims that a 50m agent
can meet a ten-second revocation deadline or that a 16-PID process is safe
under rotation. Equivalent image targets do not merge resource quotas.

| Duty | MiB | mCPU | PIDs |
| --- | ---: | ---: | ---: |
| browser_action_ingress_runtime | 128 | 200 | 32 |
| browser_executor, browser_role | 128 | 150 | 32 |
| break_glass_controller, egress_policy_authority | 64 | 50 | 16 |
| certificate_controller, credential_controller | 128 | 200 | 32 |
| chromium_sandbox | 1024 | 1000 | 256 |
| desktop_executor, desktop_role | 128 | 150 | 32 |
| desktop_x11_sandbox | 512 | 1000 | 128 |
| egress_broker | 96 | 100 | 32 |
| gateway_runtime, product_runtime | 256 | 300 | 64 |
| guest_runtime | 128 | 200 | 32 |
| migration_job | 128 | 250 | 32 |
| migration_material_agent, runtime_material_agent | 96 | 100 | 32 |
| provider_browser_runtime, provider_coding_runtime, provider_desktop_runtime | 256 | 300 | 64 |
| public_ingress_relay | 64 | 50 | 16 |
| tls_agent | 64 | 50 | 16 |

External assumptions: `postgres` and `vault` each 512 MiB / 500m / 128
PIDs; `action-history-postgres` 256 / 300m / 128;
`capacity-valkey` 256 / 200m / 64; `dns` 128 / 100m / 32. Five services
are included in every lifecycle envelope; the four one-shot migration
bundles are each counted with their real agents and signer processes.

At these limits the source-level steady envelope sums to 7,680 MiB,
7,750m CPU and 2,096 PIDs; simultaneous Browser and Desktop sandboxes sum
to 9,216 MiB, 9,750m CPU and 2,480 PIDs. On 2026-09-29 Docker Desktop
reported 12,526,370,816 bytes of VM memory and ten CPUs. The active
envelope therefore leaves only 250m of nominal CPU quota before Docker,
observers and cleanup reserve; **host admission is not established**, and
this candidate may be infeasible without measured recalibration or a
separately approved host budget. The memory difference also is not usable
headroom until daemon/kernel, writable-layer, Vault/PostgreSQL and recorder
growth are observed.

The only existing media snapshots were short component runs: Chromium
64,462,848-byte memory peak / 56 PIDs with nonzero throttling under 1 CPU;
Desktop 117,751,808 bytes / 74 PIDs with 6 of 9 periods throttled in one
high-UID run under 1 CPU. They do not measure concurrent Browser+Desktop
sessions, credential churn, migration or fault pressure. The proposed 1024
MiB/256-PID and 512 MiB/128-PID tiers provide nominal margin over those
snapshots, not evidence that the margin is sufficient. There is no live
sample for the 50m/16-PID classes.

Freeze any candidate before a real run. A limit/policy change ends and
exactly cleans that run, then requires a fresh run ID. The final gate must
measure representative startup, rotation/revocation, migration, media/input,
pressure and faults; inspect actual cgroups, applied seccomp and UID/GID for
every deployment; enforce host overhead and cleanup reserve; and pass all
16 scenarios and zero-resource cleanup in one immutable run. Until then
Phase 6 remains **5/15**.

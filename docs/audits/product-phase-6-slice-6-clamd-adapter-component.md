# Slice 6 ClamD adapter component receipt (2026-10-05)

This is a local, dirty-source component receipt, **not** a Slice 6 scenario,
current-rule qualification, release manifest or production-readiness claim.
Sandbox accepted only this bounded real-engine/Unix-adapter component under
`S6-Clamd-real-adapter-component-accepted-20261005`.

- Exact opt-in command: `SANDBOX_RUNTIME_ARTIFACT_SCANNER_CLAMD_INTEGRATION=1 mise exec go@1.26.8 -- env -u GOROOT GOFLAGS= GOTOOLCHAIN=local go test -tags=integration -run '^TestClamdPinnedImageUnixIntegration$' -count=1 -v ./internal/artifactscanner`
- Tool command `exec-26c0497d-ac8d-4848-836d-34f71fac3188`: exit 0, wall 13.244543375 seconds. Tagged test duration 12.78 seconds.
- HEAD at run: `c22d5340e3ea30ea67e3e0fc64be00c5e147cd63`; worktree dirty, so HEAD alone does not contain this source.
- Test entry source SHA-256: `763c308ceea23ee4a20ad6fceb676a84b8f09fa60bc8350653294983298a8535`; probe source SHA-256: `c0de544be0512da99e891c718285bba45a004aa941ec955456ebe7058bdb3416`.
- Source-subset digest printed by the test: `sha256:b7a70b03683707b59e757e25956cc3536ebcfcd2782a6932ba7be259df28ac75`. The subset is exactly `go.mod`, `go.sum`, `internal/artifactscanner/clamd.go`, `internal/artifactscanner/clamd_integration_test.go`, `internal/artifactscanner/testprobe/main.go`, `internal/restrictedunix/socket.go`, `provider/artifact/model.go`; it is not a full clean tree digest.
- Cross-built probe: Go 1.26.8, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 -tags=integration -trimpath -buildvcs=true`, binary `sha256:fdfeeaa4a9079a02aa640c267f7f8d444f400d396611d6ee3fe7202535beb3ec`.
- Local-only pinned image: `clamav/clamav@sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3`; no pull, network or updater during the run.

Raw passing test output:

```text
=== RUN   TestClamdPinnedImageUnixIntegration
    clamd_integration_test.go:97: probe build: go=go1.26.8 binary_go=go1.26.8 GOOS=linux GOARCH=arm64 CGO_ENABLED=0 tags=integration trimpath buildvcs=true head=c22d5340e3ea30ea67e3e0fc64be00c5e147cd63 dirty=true source_subset=sha256:b7a70b03683707b59e757e25956cc3536ebcfcd2782a6932ba7be259df28ac75 binary=sha256:fdfeeaa4a9079a02aa640c267f7f8d444f400d396611d6ee3fe7202535beb3ec image=clamav/clamav@sha256:6d0680780fd29855cb7018f68272cb520821f614259e2066f8ec669069ac91b3
    clamd_integration_test.go:153: real adapter result: benign=clean EICAR=infected config=sha256:c657038742d626c5fc869ef496095660ed68900b3da6fa57e4e13603aae23de9 rules=map[bytecode.cvd:sha256:6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb daily.cvd:sha256:0f7520addba76ca2fc500a95a9da946f3f12de512b42f861f7f89a4fddeb2375 main.cvd:sha256:0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365] (stale image rules; no readiness claim)
--- PASS: TestClamdPinnedImageUnixIntegration (12.78s)
PASS
ok  	github.com/shell-echo/sandbox-runtime/internal/artifactscanner	13.153s
```

The test asserted exact UID/GID `1000:1000`, private Unix PING, benign clean,
raw 68-byte EICAR infected, three rule-file hashes, config hash,
`State.Running=false`, `ExitCode=0`, `OOMKilled=false`, owner-label/ID-checked
removal and a successful empty exact-name Docker query. Post-run external
queries returned no `sr-clamd-it-*` container or `sr-clamd-probe-*` host
directory. The image-embedded rule set was already outside the 72-hour
trusted-current-check window; no independent current-rule, Profile/CRL,
service composition, deployment or 16-scenario result is claimed.

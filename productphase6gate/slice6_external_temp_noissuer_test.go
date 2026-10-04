//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ExternalTempNoIssuerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_EXTERNAL_TEMP_NO_ISSUER"
const slice6TerminalExpectedDigestEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_BINARY_EXPECTED_DIGEST"

// Hold every actual Gate-owned temporary directory and all three built tools
// live through the finish-equivalent source check. Real non-root mounts and
// external expected hashes are checked without allocating a Vault issuer.
func TestSlice6ActualExternalTempsAndMountsNoIssuer(t *testing.T) {
	if os.Getenv(slice6ExternalTempNoIssuerEnv) != "1" {
		t.Skip("set " + slice6ExternalTempNoIssuerEnv + "=1 with externally frozen R/F/E and binary digests")
	}
	if os.Getenv(slice6VaultTrustSwitchEnv) == "1" {
		t.Fatal("external temporary admission must not run the issuer gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	eRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	eRevision := os.Getenv(slice6ProductObserverRevisionEnv)
	rRoot := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	rRevision := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")
	fRoot := os.Getenv(slice6GuestFixtureSourceRootEnv)
	fRevision := os.Getenv(slice6GuestFixtureSourceRevisionEnv)
	for _, source := range []struct{ root, revision string }{
		{eRoot, eRevision}, {rRoot, rRevision}, {fRoot, fRevision},
	} {
		if verifyCleanSlice6Source(ctx, source.root, source.revision) != nil {
			t.Fatal("preissuer E/R/F source must be clean and independently frozen")
		}
	}
	if slice6VerifyGuestFixtureSourcePair(ctx, rRoot, rRevision, fRoot, fRevision) != nil {
		t.Fatal("preissuer R/F fixture source pair unavailable")
	}
	observer, err := slice6BuildProductRuntimeObserver(t, ctx, eRoot)
	if err != nil || slice6ApproveProductRuntimeObserver(
		os.Getenv(slice6ProductObserverExpectedDigestEnv), &observer) != nil {
		t.Fatal("externally frozen E Product observer unavailable", err)
	}
	fixture, err := slice6BuildGuestBindingFixture(t, ctx, fRoot, fRevision)
	if err != nil || slice6ApproveGuestBindingFixture(&fixture,
		os.Getenv(slice6GuestBindingFixtureExpectedDigestEnv)) != nil {
		t.Fatal("externally frozen F Guest fixture unavailable", err)
	}
	operatorDir := slice6PrivateSourceSibling(t, rRoot, ".sr-p6-terminal-operator-")
	terminalPath, terminalDigest := slice6BuildTerminalOperator(t, ctx, operatorDir, rRoot, rRevision)
	if terminalDigest == "" || terminalDigest != os.Getenv(slice6TerminalExpectedDigestEnv) {
		t.Fatal("externally frozen R terminal binary unavailable")
	}
	root := slice6PrivateSourceSibling(t, rRoot, ".sr-vault-trust-switch-")
	for _, subdir := range []string{"config", "data"} {
		if err := os.Mkdir(filepath.Join(root, subdir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{
		".sr-product-identity-observer-", ".sr-guest-material-observer-", ".sr-guest-signer-observer-",
	} {
		slice6PrivateSourceSibling(t, eRoot, prefix)
	}
	for _, source := range []struct{ root, revision string }{
		{eRoot, eRevision}, {rRoot, rRevision}, {fRoot, fRevision},
	} {
		if verifyCleanSlice6Source(ctx, source.root, source.revision) != nil {
			t.Fatal("live run-owned temporary files dirtied frozen E/R/F before finish")
		}
	}
	if err := slice6ProbeProductRuntimeObserverMount(ctx, observer); err != nil {
		t.Fatal("E observer non-root mount unavailable", err)
	}
	identity := phase6security.Slice6DesiredUIDGID()["product-runtime"]
	if err := slice6ProbeGuestBindingFixtureMount(ctx, fixture, identity[0], identity[1]); err != nil {
		t.Fatal("F fixture non-root mount unavailable", err)
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("noissuer terminal probe exact Docker cleanup: %v", err)
		}
	})
	slice6RequireTerminalOperatorV2Capability(t, ctx, run, terminalPath, terminalDigest)
	for _, source := range []struct{ root, revision string }{
		{eRoot, eRevision}, {rRoot, rRevision}, {fRoot, fRevision},
	} {
		if verifyCleanSlice6Source(ctx, source.root, source.revision) != nil {
			t.Fatal("post-mount finish-equivalent E/R/F source check failed")
		}
	}
	t.Log("externally frozen E/R/F tools, all live external temporary classes, three non-root Docker mounts and strict finish-equivalent source checks passed without issuer")
}

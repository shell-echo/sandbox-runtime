//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// Read immutable-source locations once, before starting the issuer. The
// composition reopens these same sources after the real CA is generated.
type slice6VaultStaticInputs struct {
	sourceRoot, sourceRevision, terminalSourceRoot   string
	roleCandidates, desktopCandidate, browserArchive string
	external                                         phase6profilebuilder.ExternalImageInputs
}

func slice6VaultStaticInputsFromEnvironment() slice6VaultStaticInputs {
	sourceRoot := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	return slice6VaultStaticInputs{
		sourceRoot: sourceRoot, sourceRevision: os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION"),
		terminalSourceRoot: os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_OPERATOR_SOURCE_ROOT"),
		roleCandidates:     os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_ROLE_CANDIDATES"),
		desktopCandidate:   os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"),
		browserArchive:     os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_BROWSER_ARCHIVE"),
		external: phase6profilebuilder.ExternalImageInputs{SourceRoot: sourceRoot, Platform: "linux/arm64/v8",
			Vault: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_SELECTED")},
			Postgres: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_SELECTED")},
			Valkey: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_SELECTED")},
			DNS: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_SELECTED")},
		},
	}
}

func slice6VaultPreflightStaticInputs(ctx context.Context, input slice6VaultStaticInputs) error {
	if ctx == nil || ctx.Err() != nil || !absoluteCleanSlice6Path(input.sourceRoot) ||
		!absoluteCleanSlice6Path(input.terminalSourceRoot) ||
		len(input.sourceRevision) != 40 || !lowerHexSlice6(input.sourceRevision) {
		return errors.New("Vault source-bound static inputs unavailable")
	}
	source, sourceErr := filepath.EvalSymlinks(input.sourceRoot)
	terminal, terminalErr := filepath.EvalSymlinks(input.terminalSourceRoot)
	if sourceErr != nil || terminalErr != nil || source != terminal ||
		verifyCleanSlice6Source(ctx, source, input.sourceRevision) != nil {
		return errors.New("Vault and terminal operator must use the same clean source revision")
	}
	external, err := phase6profilebuilder.LoadExternalImageSupply(ctx, input.external)
	if err != nil || len(external.Bindings()) != len(phase6security.Slice6DesiredExternalServiceNames()) ||
		external.VerifySources(ctx) != nil {
		return errors.New("Vault complete external image archives unavailable")
	}
	images, err := phase6profilebuilder.LoadImageSupply(ctx, input.sourceRoot, input.sourceRevision,
		input.roleCandidates, input.desktopCandidate, input.browserArchive)
	if err != nil || len(images.LocalRoleTargets) != len(phase6security.Slice6DesiredLocalRoleTargets()) ||
		images.Platform != input.external.Platform || images.VerifySources(ctx) != nil {
		return errors.New("Vault source-bound role, Desktop or Browser image supply unavailable")
	}
	return nil
}

// This uses the same admission function as the live gate, but never allocates
// a Docker run or starts an issuer. The selected-only Vault archive is a
// deliberately incomplete OCI input from the operator's private test supply.
func TestSlice6VaultPreIssuerStaticInputRejections(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_STATIC_INPUT_REJECTION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_STATIC_INPUT_REJECTION=1 with source and archive inputs")
	}
	static := slice6VaultStaticInputsFromEnvironment()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	oldSource := static
	oldSource.sourceRevision = strings.Repeat("0", 40)
	if err := slice6VaultPreflightStaticInputs(ctx, oldSource); ctx.Err() != nil || err == nil ||
		!strings.Contains(err.Error(), "same clean source revision") {
		t.Fatalf("stale source must fail before issuer allocation: %v", err)
	}
	incomplete := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_INCOMPLETE_VAULT_ARCHIVE")
	if !absoluteCleanSlice6Path(incomplete) {
		t.Fatal("private selected-only Vault archive required for pre-issuer regression")
	}
	static.external.Vault.Path = incomplete
	if err := slice6VaultPreflightStaticInputs(ctx, static); ctx.Err() != nil || err == nil ||
		!strings.Contains(err.Error(), "complete external image archives") {
		t.Fatalf("Vault OCI archive missing layers must fail before issuer allocation: %v", err)
	}
	t.Log("stale source and selected-only Vault archive rejected without a Docker run, Vault or issuer")
}

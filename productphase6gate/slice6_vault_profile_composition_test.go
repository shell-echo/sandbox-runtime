//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This optional diagnostic freezes a complete source-bound desired Profile
// while the same-run real Vault issuers are still live. It does not launch the
// controller or prove that all five external services use these trust roots.
func slice6VaultComposeCandidateProfile(t *testing.T, ctx context.Context, root, runID string,
	general, broker slice6VaultRoot) {
	t.Helper()
	directory := filepath.Join(root, "composition")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("create private composition inputs")
	}
	anchors := make(map[string]string)
	for _, anchor := range phase6security.Slice6DesiredFinalTrustAnchorTemplates() {
		bundle, err := slice6VaultCompositionAnchorBundle(anchor.ID, general.PEM, broker.PEM)
		if err != nil {
			t.Fatal("unreviewed composition trust-anchor purpose")
		}
		path := filepath.Join(directory, anchor.ID+".pem")
		if err := os.WriteFile(path, bundle, 0o400); err != nil {
			t.Fatal("write real purpose-bound public trust anchor")
		}
		anchors[anchor.ID] = path
	}
	brokerPath := filepath.Join(directory, "dns-broker-client-ca.pem")
	if err := os.WriteFile(brokerPath, broker.PEM, 0o400); err != nil {
		t.Fatal("write real broker-only public CA")
	}
	writeKeys := func(names []string) map[string]string {
		t.Helper()
		paths := make(map[string]string, len(names))
		for _, name := range names {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("generate run-owned private key")
			}
			path := filepath.Join(directory, name+".key")
			if err := os.WriteFile(path, private, 0o600); err != nil {
				clear(private)
				t.Fatal("write run-owned private key")
			}
			clear(private)
			paths[name] = path
		}
		return paths
	}
	identityDigest := func(domain string) string {
		sum := sha256.Sum256([]byte(domain + "\x00" + runID))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	sourceRoot := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	input := phase6profilebuilder.CompositionInputs{
		Images: phase6profilebuilder.ImageDraftInputs{
			RunID: runID, EnvironmentDigest: identityDigest("slice6-diagnostic-environment"),
			PrincipalProfileDigest: identityDigest("slice6-diagnostic-principal-profile"),
			SourceRoot:             sourceRoot, SourceRevision: os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION"),
			RoleCandidateDirectory: os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_ROLE_CANDIDATES"),
			DesktopCandidatePath:   os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"),
			BrowserArchivePath:     os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_BROWSER_ARCHIVE"),
		},
		TrustAnchors: anchors,
		ExternalImages: phase6profilebuilder.ExternalImageInputs{SourceRoot: sourceRoot, Platform: "linux/arm64/v8",
			Vault: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_SELECTED")},
			Postgres: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_SELECTED")},
			Valkey: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_SELECTED")},
			DNS: phase6profilebuilder.ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_ARCHIVE"),
				SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_SELECTED")},
		},
		DNSClientCA:     phase6profilebuilder.DNSClientCAInput{BundlePath: brokerPath, IssuerID: broker.ID},
		EgressKeys:      writeKeys(phase6security.Slice6DesiredEgressAuthorityNames()),
		CertificateKeys: writeKeys(phase6security.Slice6DesiredCertificateKeyIDs()),
	}
	candidate, err := phase6profilebuilder.ComposeSlice6CandidateProfile(ctx, input, time.Now().UTC())
	if err != nil || candidate.Profile.Validate() != nil ||
		phase6security.VerifySlice6FinalGateProfile(candidate.Profile) != nil {
		t.Fatalf("real-issuer source-bound profile composition failed: %v", err)
	}
	diagnostics := candidate.Diagnostics()
	if diagnostics.ImageSupplyLoads != 2 || diagnostics.ExternalArchivePasses != 2 ||
		len(diagnostics.Stages) != 9 || diagnostics.Stages[len(diagnostics.Stages)-1].Name != "final_source_reopen" {
		t.Fatalf("unexpected full source verification passes: image=%d external=%d stages=%v",
			diagnostics.ImageSupplyLoads, diagnostics.ExternalArchivePasses, diagnostics.Stages)
	}
	for _, stage := range diagnostics.Stages {
		t.Logf("source-bound composition stage=%s duration=%s", stage.Name, stage.Duration)
	}
	document, err := json.Marshal(candidate.Profile)
	if err != nil {
		t.Fatal("marshal composed profile")
	}
	profilePath := filepath.Join(directory, "candidate-profile.json")
	if err := os.WriteFile(profilePath, document, 0o600); err != nil {
		t.Fatal("write run-owned candidate profile")
	}
	verified, err := phase6security.VerifyFile(profilePath)
	if err != nil || verified.ProfileDigest != candidate.Profile.ProfileDigest || len(verified.Principals) != 82 {
		t.Fatal("reopen real-issuer source-bound profile")
	}
	gateInput, err := loadSlice6GateInput(ctx, profilePath, sourceRoot, input.Images.SourceRevision,
		input.Images.DesktopCandidatePath, input.Images.RoleCandidateDirectory)
	if err != nil || len(gateInput.roleCandidates) != len(phase6security.Slice6DesiredLocalRoleTargets()) ||
		gateInput.profile.ProfileDigest != verified.ProfileDigest {
		t.Fatalf("same-run candidate failed strict Slice 6 gate input preflight: %v", err)
	}
	loadedImages, err := verifySlice6LoadedImageStore(ctx, gateInput)
	if err != nil {
		t.Fatalf("same-run candidate image store preflight failed: %v", err)
	}
	anchorPath := anchors[phase6security.Slice6DesiredFinalTrustAnchorTemplates()[0].ID]
	originalAnchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal("read run-owned anchor before mutation")
	}
	if err := os.Chmod(anchorPath, 0o600); err != nil {
		t.Fatal("prepare run-owned anchor mutation")
	}
	defer func() {
		if err := os.Chmod(anchorPath, 0o600); err != nil {
			t.Errorf("prepare run-owned anchor restore: %v", err)
			return
		}
		if err := os.WriteFile(anchorPath, originalAnchor, 0o600); err != nil {
			t.Errorf("restore run-owned anchor bytes: %v", err)
		}
		if err := os.Chmod(anchorPath, 0o400); err != nil {
			t.Errorf("restore run-owned anchor mode: %v", err)
		}
	}()
	if err := os.WriteFile(anchorPath, broker.PEM, 0o600); err != nil {
		t.Fatal("mutate run-owned anchor source")
	}
	if err := os.Chmod(anchorPath, 0o400); err != nil {
		t.Fatal("restore read-only mode on mutated anchor")
	}
	if ctx.Err() != nil || candidate.VerifySources(ctx, time.Now().UTC()) == nil {
		t.Fatal("post-freeze source mutation was not rejected")
	}
	t.Logf("real-issuer source-bound desired Profile=%s principals=%d role_candidates=%d loaded_images=%d; gate input preflight only, no controller launch, external service-chain or Slice 6 evidence",
		verified.ProfileDigest, len(verified.Principals), len(gateInput.roleCandidates), loadedImages)
}

// The five anchor names are trust purposes, not five independent CAs. The
// local egress-broker server edges require broker-only in internal-server;
// ordinary local clients and the external service/server paths use general.
func slice6VaultCompositionAnchorBundle(id string, general, broker []byte) ([]byte, error) {
	general, broker = bytes.TrimSpace(general), bytes.TrimSpace(broker)
	if len(general) == 0 || len(broker) == 0 || bytes.Equal(general, broker) {
		return nil, phase6profilebuilder.ErrInvalidTrustAnchorSupply
	}
	general = append(bytes.Clone(general), '\n')
	broker = append(bytes.Clone(broker), '\n')
	switch id {
	case "external-server-ca", "internal-client-ca", "postgres-client-ca", "vault-client-ca":
		return bytes.Clone(general), nil
	case "internal-server-ca":
		return append(bytes.Clone(general), broker...), nil
	default:
		return nil, phase6profilebuilder.ErrInvalidTrustAnchorSupply
	}
}

func TestSlice6VaultCompositionAnchorBundleMapping(t *testing.T) {
	general, broker := []byte("general\n"), []byte("broker\n")
	for _, anchor := range phase6security.Slice6DesiredFinalTrustAnchorTemplates() {
		got, err := slice6VaultCompositionAnchorBundle(anchor.ID, general, broker)
		want := general
		if anchor.ID == "internal-server-ca" {
			want = []byte("general\nbroker\n")
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("incorrect issuer set for %s: %v", anchor.ID, err)
		}
	}
	for _, id := range []string{"", "dns-client-ca", "unknown"} {
		if _, err := slice6VaultCompositionAnchorBundle(id, general, broker); err == nil {
			t.Fatalf("unreviewed purpose %q accepted", id)
		}
	}
	withoutTrailingNewline, err := slice6VaultCompositionAnchorBundle("internal-server-ca", []byte("general"), []byte("broker"))
	if err != nil || !bytes.Equal(withoutTrailingNewline, []byte("general\nbroker\n")) {
		t.Fatal("Vault PEM without trailing newline was not separated canonically")
	}
}

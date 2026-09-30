//go:build integration

package phase6profilebuilder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// These opt-in checks reopen complete pinned OCI archives and every compressed
// layer/diff ID. Each result is an input component, not a live service or the
// complete Slice 6 profile. The full four-archive supply remains separate.
func TestPinnedExternalArchiveComponent(t *testing.T) {
	const platform = "linux/arm64/v8"
	for _, item := range []struct {
		name, reference, archiveEnv, selectedEnv string
	}{
		{"vault", slice6VaultImage, "SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE", "SANDBOX_RUNTIME_PHASE6_VAULT_SELECTED"},
		{"postgres", slice6PostgresImage, "SANDBOX_RUNTIME_PHASE6_POSTGRES_ARCHIVE", "SANDBOX_RUNTIME_PHASE6_POSTGRES_SELECTED"},
		{"valkey", slice6ValkeyImage, "SANDBOX_RUNTIME_PHASE6_VALKEY_ARCHIVE", "SANDBOX_RUNTIME_PHASE6_VALKEY_SELECTED"},
		{"dns", slice6DNSImage, "SANDBOX_RUNTIME_PHASE6_DNS_ARCHIVE", "SANDBOX_RUNTIME_PHASE6_DNS_SELECTED"},
	} {
		t.Run(item.name, func(t *testing.T) {
			path, selected := os.Getenv(item.archiveEnv), os.Getenv(item.selectedEnv)
			if path == "" && selected == "" {
				t.Skip("set both private complete archive and selected manifest environment values")
			}
			binding, proof, err := verifyExternalArchive(ExternalArchive{Path: path,
				SelectedManifestDigest: selected}, item.reference, platform)
			if err != nil || binding.ConfigDigest == "" || proof == "" {
				t.Fatalf("pinned external OCI archive rejected: %v", err)
			}
			t.Logf("verified index=%s selected=%s config=%s proof=%s", binding.Digest,
				binding.SelectedManifestDigest, binding.ConfigDigest, proof)
		})
	}
}

// This is the complete five-name image-input set (four complete archives),
// still before the profile, running containers, TLS identities or scenarios.
func TestFullPinnedExternalImageSupply(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_FULL_EXTERNAL_IMAGE_SUPPLY") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_FULL_EXTERNAL_IMAGE_SUPPLY=1 for all four private archives")
	}
	input := externalImageInputsFromEnv(t)
	supply, err := LoadExternalImageSupply(context.Background(), input)
	if err == nil {
		err = supply.VerifySources(context.Background())
	}
	bindings, proofs := supply.Bindings(), supply.DescriptorProofs()
	if err != nil || len(bindings) != 5 || len(proofs) != 5 ||
		bindings["action-history-postgres"] != bindings["postgres"] ||
		proofs["action-history-postgres"] != proofs["postgres"] {
		t.Fatalf("complete pinned external image input unavailable: %v", err)
	}
	services, err := supply.BindExternalServices()
	if err != nil || len(services) != 5 {
		t.Fatalf("reviewed external service skeleton unavailable: %v", err)
	}
	t.Log("four independently verified complete OCI archives bind all five reviewed service names; no profile or deployment")
}

// This exercises the public source-reopening topology binder with real pinned
// external archives. The other draft inputs are test-owned synthetic CA and
// image/resource policy, so it is not a launchable profile or release gate.
func TestFullPinnedExternalTopologyComponent(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_FULL_EXTERNAL_IMAGE_SUPPLY") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_FULL_EXTERNAL_IMAGE_SUPPLY=1 for all four private archives")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	supply, err := LoadExternalImageSupply(ctx, externalImageInputsFromEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	draft := testSlice6TrustDraft(t)
	bound, err := BindSlice6FinalTopologyDraft(ctx, draft, supply, time.Now().UTC())
	if err != nil || len(bound.External) != 5 || len(bound.TrustEdges) != 152 ||
		phase6security.VerifySlice6DesiredFinalNetworks(bound.Networks) != nil {
		t.Fatalf("source-bound final topology component unavailable: %v", err)
	}
	t.Log("reopened real pinned external OCI bytes under a synthetic non-launchable draft; no live service or final profile")
}

func externalImageInputsFromEnv(t *testing.T) ExternalImageInputs {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return ExternalImageInputs{SourceRoot: root, Platform: "linux/arm64/v8",
		Vault: ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_ARCHIVE"),
			SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VAULT_SELECTED")},
		Postgres: ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_ARCHIVE"),
			SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_POSTGRES_SELECTED")},
		Valkey: ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_ARCHIVE"),
			SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_VALKEY_SELECTED")},
		DNS: ExternalArchive{Path: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_ARCHIVE"),
			SelectedManifestDigest: os.Getenv("SANDBOX_RUNTIME_PHASE6_DNS_SELECTED")},
	}
}

// This checks Docker's actual store and selected platform for four stopped,
// networkless observation containers. It does not start the external services,
// validate their credentials or admit a Slice 6 deployment.
func TestDockerPinnedExternalImageSelections(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_DOCKER_EXTERNAL_IMAGE_SELECTION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_DOCKER_EXTERNAL_IMAGE_SELECTION=1 with all four private archives")
	}
	input := externalImageInputsFromEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	supply, err := LoadExternalImageSupply(ctx, input)
	if err != nil {
		t.Fatalf("complete pinned archive set unavailable: %v", err)
	}
	bindings := supply.Bindings()
	for _, item := range []struct {
		name    string
		archive ExternalArchive
	}{
		{"vault", input.Vault}, {"postgres", input.Postgres},
		{"capacity-valkey", input.Valkey}, {"dns", input.DNS},
	} {
		t.Run(item.name, func(t *testing.T) {
			binding := bindings[item.name]
			documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(item.archive.Path,
				binding.Location, binding.Kind, binding.Reference, binding.Digest,
				binding.Platform, binding.SelectedManifestDigest)
			if err != nil || proof.ConfigDigest != binding.ConfigDigest ||
				phase6security.VerifyOCIArchiveLayers(item.archive.Path, documents.Manifest, documents.Config) != nil {
				t.Fatal("verified external archive changed before Docker selection")
			}
			imageDocument, err := dockerExternalImage(ctx, "image", "inspect", binding.Reference)
			if err != nil {
				t.Fatalf("pinned Docker store image unavailable: %v", err)
			}
			name := fmt.Sprintf("p6-external-image-%s-%d", item.name, time.Now().UnixNano())
			if _, err := dockerExternalImage(ctx, "inspect", name); err == nil {
				t.Fatal("observation container name already exists")
			}
			var volumeNames []string
			t.Cleanup(func() {
				cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
				defer stop()
				if _, inspectErr := dockerExternalImage(cleanupCtx, "inspect", name); inspectErr == nil {
					if _, removeErr := dockerExternalImage(cleanupCtx, "rm", "-f", "-v", name); removeErr != nil {
						t.Errorf("remove exact observation container: %v", removeErr)
					}
				}
				if _, inspectErr := dockerExternalImage(cleanupCtx, "inspect", name); inspectErr == nil {
					t.Error("observation container remained after cleanup")
				}
				for _, volume := range volumeNames {
					if _, inspectErr := dockerExternalImage(cleanupCtx, "volume", "inspect", volume); inspectErr == nil {
						t.Error("observation container anonymous volume remained after cleanup")
					}
				}
			})
			containerID, err := dockerExternalImage(ctx, "create", "--pull=never", "--network", "none",
				"--platform", binding.Platform, "--name", name, binding.Reference)
			containerID = strings.TrimSpace(containerID)
			if err != nil {
				t.Fatalf("create networkless observation container: %v", err)
			}
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(containerID) {
				t.Fatal("Docker returned a noncanonical container ID")
			}
			containerDocument, err := dockerExternalImage(ctx, "inspect", containerID)
			if err != nil {
				t.Fatalf("inspect exact observation container: %v", err)
			}
			var containers []struct {
				ID     string `json:"Id"`
				Name   string `json:"Name"`
				Mounts []struct {
					Type string `json:"Type"`
					Name string `json:"Name"`
				} `json:"Mounts"`
			}
			if json.Unmarshal([]byte(containerDocument), &containers) != nil || len(containers) != 1 ||
				containers[0].ID != containerID || containers[0].Name != "/"+name {
				t.Fatal("malformed Docker observation container inspect")
			}
			for _, mount := range containers[0].Mounts {
				if mount.Type == "volume" {
					volumeNames = append(volumeNames, mount.Name)
				}
			}
			observed, err := phase6security.ObserveDockerRuntimeImage([]byte(containerDocument),
				[]byte(imageDocument), binding.Location, binding.Kind, binding.Reference,
				binding.Digest, binding.Platform, binding.SelectedManifestDigest, binding.ConfigDigest, documents)
			if err != nil || observed.SelectedManifestDescriptor.Digest != binding.SelectedManifestDigest ||
				observed.OCIConfigDigest != binding.ConfigDigest || observed.RuntimeStoreImageID != binding.Digest ||
				observed.DescriptorProofDigest != proof.ProofDigest {
				t.Fatalf("Docker platform/config selection differs from verified archive: %v", err)
			}
			t.Logf("observed pinned Docker index=%s selected=%s config=%s", binding.Digest,
				binding.SelectedManifestDigest, binding.ConfigDigest)
		})
	}
}

func dockerExternalImage(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	result, err := command.CombinedOutput()
	if err != nil || len(result) > 8<<20 {
		return "", ErrInvalidExternalImageSupply
	}
	return string(result), nil
}

//go:build integration

package desktopcandidate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This is component evidence for the exact local image supplied by the
// operator, never a clean-source candidate record or a Slice 6 gate.
func TestDesktopCandidateArchiveNSSIntegration(t *testing.T) {
	image := os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_IMAGE")
	build := os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_BUILD") == "1"
	if image == "" && !build {
		t.Skip("set SANDBOX_RUNTIME_DESKTOP_CANDIDATE_BUILD=1 or SANDBOX_RUNTIME_DESKTOP_CANDIDATE_IMAGE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	command := func(arguments ...string) []byte {
		t.Helper()
		output, err := exec.CommandContext(ctx, "docker", arguments...).Output()
		if err != nil {
			t.Fatalf("docker %s: %v", arguments[0], err)
		}
		return output
	}
	accounts := AccountAllowlist{Schema: AccountAllowlistSchema, Accounts: []WorkloadAccount{{UID: 20000, GID: 30000}, {UID: 20001, GID: 30001}}}
	if build {
		platform := "linux/amd64"
		if runtime.GOARCH == "arm64" {
			platform = "linux/arm64/v8"
		}
		accountDocument, err := json.Marshal(accounts)
		if err != nil {
			t.Fatal(err)
		}
		accountPath := filepath.Join(t.TempDir(), "workload-accounts.json")
		if err := os.WriteFile(accountPath, accountDocument, 0o600); err != nil {
			t.Fatal(err)
		}
		image = "sandbox-runtime-desktop:nss-proof-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + time.Now().UTC().Format("20060102150405")
		buildCommand := exec.CommandContext(ctx, "./build-phase6-locked.sh", platform, image, "integration-test", accountPath)
		buildCommand.Dir = filepath.Join("..", "..", "profiles", "desktop", "image")
		if output, err := buildCommand.CombinedOutput(); err != nil {
			t.Fatalf("build local Desktop candidate: %v: %.512s", err, output)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			_ = exec.CommandContext(cleanup, "docker", "image", "rm", image).Run()
		})
	}
	var images []struct {
		ID         string `json:"Id"`
		Descriptor struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(command("image", "inspect", image), &images) != nil || len(images) != 1 || images[0].ID != images[0].Descriptor.Digest {
		t.Fatal("local candidate store identity unavailable")
	}
	container := strings.TrimSpace(string(command("create", "--pull=never", "--network=none", images[0].ID)))
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", container).Run()
	})
	var containers []struct {
		ImageManifestDescriptor struct {
			Digest string `json:"digest"`
		} `json:"ImageManifestDescriptor"`
	}
	if json.Unmarshal(command("inspect", container), &containers) != nil || len(containers) != 1 {
		t.Fatal("candidate selected manifest unavailable")
	}
	archive := filepath.Join(t.TempDir(), "candidate.oci.tar")
	command("image", "save", "-o", archive, images[0].ID)
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	kind := phase6security.ImageIdentityOCIManifest
	if strings.Contains(images[0].Descriptor.MediaType, "index") || strings.Contains(images[0].Descriptor.MediaType, "manifest.list") {
		kind = phase6security.ImageIdentityOCIIndex
	}
	selected := containers[0].ImageManifestDescriptor.Digest
	documents, err := phase6security.ReadOCIArchiveDocuments(archive, kind, images[0].ID, selected, "")
	if err != nil {
		t.Fatal(err)
	}
	var selectedManifest struct {
		Layers []json.RawMessage `json:"layers"`
	}
	if json.Unmarshal(documents.Manifest, &selectedManifest) != nil {
		t.Fatal("selected candidate manifest is invalid")
	}
	t.Logf("real candidate selected manifest layers=%d", len(selectedManifest.Layers))
	for index, layer := range selectedManifest.Layers {
		var descriptor struct {
			MediaType string `json:"mediaType"`
			Size      int64  `json:"size"`
		}
		if json.Unmarshal(layer, &descriptor) != nil {
			t.Fatal("candidate layer descriptor invalid")
		}
		t.Logf("layer %d media=%s size=%d", index, descriptor.MediaType, descriptor.Size)
	}
	if err := verifyArchiveAccounts(archive, documents.Manifest, accounts); err != nil {
		t.Fatalf("real candidate archive NSS differs from manifest allowlist: %v", err)
	}
}

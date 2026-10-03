//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6StoredImageAdmissionUnit(t *testing.T) {
	if !slice6SameCanonicalRepoDigest("docker.io/library/postgres:16-alpine@sha256:"+strings.Repeat("a", 64),
		"postgres@sha256:"+strings.Repeat("a", 64)) ||
		!slice6SameCanonicalRepoDigest("docker.io/hashicorp/vault@sha256:"+strings.Repeat("a", 64),
			"hashicorp/vault@sha256:"+strings.Repeat("a", 64)) ||
		slice6SameCanonicalRepoDigest("docker.io/hashicorp/vault@sha256:"+strings.Repeat("a", 64),
			"other/vault@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("Docker Hub repository normalization changed image identity")
	}
	const digest = "sha256:" + "a"
	imageDigest := digest + strings.Repeat("a", 63)
	binding := phase6profilebuilder.ImageBinding{Reference: "registry.example.test/role@" + imageDigest,
		Digest: imageDigest, Location: "registry", Kind: "oci-index", Platform: "linux/arm64/v8"}
	items := []slice6StoredImage{{"vault", binding}, {"shared-reference", binding}}
	called := 0
	inspect := func(_ context.Context, ref string) ([]byte, error) {
		called++
		if ref != binding.Reference {
			t.Fatal("unexpected image reference")
		}
		return nil, errors.New("No such image")
	}
	err := slice6CheckStoredImages(context.Background(), items, "", inspect)
	if err == nil || !strings.Contains(err.Error(), "missing=[vault shared-reference]") || called != 1 {
		t.Fatalf("missing fixed image was not batched before create: err=%v calls=%d", err, called)
	}
	inspect = func(_ context.Context, _ string) ([]byte, error) {
		return []byte(`[{"Id":"sha256:` + strings.Repeat("b", 64) + `","Os":"linux","Architecture":"arm64","RepoDigests":["` + binding.Reference + `"],"Descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"` + imageDigest + `"}}]`), nil
	}
	err = slice6CheckStoredImages(context.Background(), items, "", inspect)
	if err == nil || !strings.Contains(err.Error(), "identity_mismatch=[vault shared-reference]") {
		t.Fatalf("wrong image identity was accepted: %v", err)
	}
}

func TestSlice6AuxiliaryImageAdmissionIncludesFiniteOperator(t *testing.T) {
	items := slice6RequiredAuxiliaryImages()
	if len(items) != 3 || items[0].digest == items[2].digest ||
		items[2].reference != "docker.io/library/alpine@"+items[2].digest {
		t.Fatal("finite task index collapsed into the prep Alpine image")
	}
	document := func(item slice6AuxiliaryImage, imageID string) []byte {
		repoDigests := []string{}
		if item.registry {
			repoDigests = append(repoDigests, item.reference)
		}
		encoded, err := json.Marshal([]map[string]any{{
			"Id": imageID, "Os": "linux", "Architecture": "arm64",
			"RepoDigests": repoDigests, "Descriptor": map[string]string{"digest": imageID},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	called := 0
	missingTask := func(_ context.Context, reference string) ([]byte, error) {
		called++
		for _, item := range items {
			if item.reference == reference {
				if item.name == "break-glass-operator-task" {
					return nil, errors.New("No such image")
				}
				return document(item, item.digest), nil
			}
		}
		t.Fatal("unknown auxiliary image reference")
		return nil, nil
	}
	err := slice6PreflightAuxiliaryImagesWithInspect(context.Background(), items, missingTask)
	if err == nil || !strings.Contains(err.Error(), "missing=[break-glass-operator-task]") || called != 3 {
		t.Fatalf("selected Alpine present concealed missing finite-task index: err=%v calls=%d", err, called)
	}
	missingAndDrift := func(_ context.Context, reference string) ([]byte, error) {
		for _, item := range items {
			if item.reference == reference {
				if item.name == "network-probe" {
					return nil, errors.New("No such image")
				}
				if item.name == "break-glass-operator-task" {
					return document(item, "sha256:"+strings.Repeat("f", 64)), nil
				}
				return document(item, item.digest), nil
			}
		}
		t.Fatal("unknown auxiliary image reference")
		return nil, nil
	}
	err = slice6PreflightAuxiliaryImagesWithInspect(context.Background(), items, missingAndDrift)
	if err == nil || !strings.Contains(err.Error(), "missing=[network-probe]") ||
		!strings.Contains(err.Error(), "identity_mismatch=[break-glass-operator-task]") {
		t.Fatalf("multiple fixed-image faults were not reported together: %v", err)
	}
	revision := strings.Repeat("a", 40)
	digest := "sha256:" + strings.Repeat("b", 64)
	artifact := phase6security.Slice6BreakGlassExecutableArtifact{
		ID: "break-glass-operator", SourceRevision: revision, SourceTreeDigest: digest,
		Toolchain: "go1.26.8", ToolchainDigest: digest,
		BuildTarget:     "./cmd/phase6-break-glass-operator",
		BuildParameters: phase6security.Slice6BreakGlassBuildParameters,
		Platform:        "linux/arm64/v8", BinaryDigest: digest, BinaryBytes: 1,
		ContainerPath: "/phase6-break-glass-operator", CarrierReference: items[2].reference,
		CarrierIndexDigest:            phase6security.Slice6BreakGlassCarrierIndexDigest,
		CarrierSelectedManifestDigest: phase6security.Slice6BreakGlassCarrierManifestDigest,
		CarrierConfigDigest:           phase6security.Slice6BreakGlassCarrierConfigDigest,
		CarrierPlatform:               "linux/arm64/v8",
	}
	task := phase6security.Slice6BreakGlassOperatorTask{ImageReference: items[2].reference,
		ExecutableArtifactID: artifact.ID, Executable: artifact.ContainerPath,
		ExecutableMount: phase6security.Mount{Target: artifact.ContainerPath,
			Kind: "read_only_executable", ReadOnly: true,
			StorageID: "break-glass-operator-source-binary"}}
	profile := phase6security.Profile{Revision: "slice6-" + revision,
		BreakGlassExecutableArtifact: artifact,
		BreakGlassOperatorTasks:      make([]phase6security.Slice6BreakGlassOperatorTask, 8)}
	for index := range profile.BreakGlassOperatorTasks {
		profile.BreakGlassOperatorTasks[index] = task
	}
	if err := slice6VerifyComposedTaskCarrier(profile); err != nil {
		t.Fatalf("composed task carrier rejected matching preissuer index: %v", err)
	}
	profile.BreakGlassOperatorTasks[7].ImageReference = items[0].reference
	if err := slice6VerifyComposedTaskCarrier(profile); err == nil {
		t.Fatal("composed task silently downgraded to selected prep-Alpine digest")
	}
}

func TestSlice6DockerCreateFailureIsBoundedAndRedacted(t *testing.T) {
	exitErr := exec.CommandContext(t.Context(), "sh", "-c", "exit 125").Run()
	if exitErr == nil {
		t.Fatal("failed to construct nonzero Docker-like exit")
	}
	for _, candidate := range []struct {
		name, output, category string
	}{
		{"image", "Error response from daemon: No such image: private.example.test/image@sha256:abc", "missing_image"},
		{"mount", "invalid mount config for type bind: /private/path", "mount"},
		{"name", "Conflict. The container name /private-name is already in use", "name_conflict"},
		{"resource", "no space left on device: /private/path", "resource"},
		{"unknown", "daemon response for /private/path token=secret", "unknown"},
		{"oversized", strings.Repeat("No such image", 500), "unknown"},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			result := slice6DockerCreateFailure(context.Background(), []byte(candidate.output), exitErr)
			if result != "class="+candidate.category+" exit=125 context=active" ||
				strings.Contains(result, "private") || strings.Contains(result, "secret") ||
				len(result) > 80 {
				t.Fatalf("Docker create category leaked or changed: %q", result)
			}
		})
	}
	if actual := slice6DockerCreateFailure(context.Background(), []byte("untrusted"), nil); actual != "class=noncanonical_response exit=0 context=active" {
		t.Fatalf("successful noncanonical create response was not classified: %s", actual)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if actual := slice6DockerCreateFailure(cancelled, []byte("No such image"), context.Canceled); actual != "class=context exit=unknown context=cancelled" {
		t.Fatalf("context cancellation was misclassified as missing image: %s", actual)
	}
}

func TestSlice6VaultCreateResponseAndRecoveryUnit(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	name := "sr-p6-vault-switch-" + run.id
	id := strings.Repeat("b", 64)
	if slice6CanonicalCreatedID([]byte("Error response from daemon: No such image"), errors.New("exit status 125")) != "" ||
		slice6CanonicalCreatedID([]byte(id), errors.New("response lost")) != "" ||
		slice6CanonicalCreatedID([]byte(id+"\n"), nil) != id {
		t.Fatal("Docker stderr or uncertain create response became a container ID")
	}
	if slice6VaultCreateAdmitted([]byte(id), errors.New("response lost"), id) ||
		slice6VaultCreateAdmitted([]byte("Docker error"), nil, id) ||
		slice6VaultCreateAdmitted([]byte(id), nil, strings.Repeat("c", 64)) ||
		!slice6VaultCreateAdmitted([]byte(id+"\n"), nil, id) {
		t.Fatal("uncertain create response incorrectly permitted Vault start")
	}
	inspect, err := json.Marshal([]map[string]any{{"Id": id, "Name": "/" + name,
		"Config": map[string]any{"Labels": map[string]string{slice6RunLabel: run.id}}}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	docker := func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		switch args[0] {
		case "ps":
			if len(args) != 7 || args[4] != "name=^/"+name+"$" || args[6] != "label="+run.label() {
				t.Fatal("recovery escaped exact name and run label")
			}
			return []byte(id + "\n"), nil
		case "inspect":
			if args[1] != id {
				t.Fatal("recovery inspected unrelated ID")
			}
			return inspect, nil
		default:
			t.Fatal("unexpected recovery Docker command")
			return nil, nil
		}
	}
	recovered, err := slice6RecoverVaultContainerWithDocker(context.Background(), run, name, docker)
	if err != nil || recovered != id || calls != 2 {
		t.Fatalf("lost create response did not recover exact container: id=%s err=%v calls=%d", recovered, err, calls)
	}
	volumes := []string{strings.Repeat("d", 64), strings.Repeat("e", 64)}
	for _, caseItem := range []struct {
		name       string
		output     []byte
		createErr  error
		startCalls int
	}{
		{"error with exact recovery", []byte(id), errors.New("response lost"), 0},
		{"noncanonical with exact recovery", []byte("Docker error"), nil, 0},
		{"wrong ID with exact recovery", []byte(strings.Repeat("c", 64)), nil, 0},
		{"success with exact recovery", []byte(id + "\n"), nil, 1},
	} {
		t.Run(caseItem.name, func(t *testing.T) {
			startCalls := 0
			start := func(_ context.Context, args ...string) ([]byte, error) {
				startCalls++
				if len(args) != 2 || args[0] != "start" || args[1] != recovered {
					t.Fatal("Vault start escaped exact recovered container")
				}
				return []byte(recovered + "\n"), nil
			}
			err := slice6StartVaultFromCreateReceipt(context.Background(), caseItem.output,
				caseItem.createErr, recovered, volumes, start)
			if startCalls != caseItem.startCalls || (err == nil) != (caseItem.startCalls == 1) {
				t.Fatalf("create uncertainty escaped cleanup-only boundary: starts=%d err=%v", startCalls, err)
			}
		})
	}
	missing := func(_ context.Context, _ ...string) ([]byte, error) { return nil, nil }
	recovered, err = slice6RecoverVaultContainerWithDocker(context.Background(), run, name, missing)
	if err != nil || recovered != "" {
		t.Fatalf("absent exact create result should remain unproved, not fabricate ID: %q %v", recovered, err)
	}
	if err := slice6StartVaultFromCreateReceipt(context.Background(), []byte(id), nil, recovered,
		volumes, func(_ context.Context, _ ...string) ([]byte, error) {
			t.Fatal("unknown create result invoked start")
			return nil, nil
		}); err == nil {
		t.Fatal("unknown create result was admitted for start")
	}
	wrong := func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte(id), nil
		}
		return []byte(`[{"Id":"` + id + `","Name":"/unrelated","Config":{"Labels":{"` + slice6RunLabel + `":"` + run.id + `"}}}]`), nil
	}
	if _, err := slice6RecoverVaultContainerWithDocker(context.Background(), run, name, wrong); err == nil {
		t.Fatal("wrong-name create recovery accepted")
	}
}

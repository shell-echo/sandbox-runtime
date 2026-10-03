//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
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

func TestSlice6VaultCreateResponseAndRecoveryUnit(t *testing.T) {
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	name := "sr-p6-vault-switch-" + run.id
	id := strings.Repeat("b", 64)
	if slice6CanonicalCreatedID([]byte("Error response from daemon: No such image"), errors.New("exit status 125")) != "" ||
		slice6CanonicalCreatedID([]byte(id), errors.New("response lost")) != "" ||
		slice6CanonicalCreatedID([]byte(id+"\n"), nil) != id {
		t.Fatal("Docker stderr or uncertain create response became a container ID")
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
	missing := func(_ context.Context, _ ...string) ([]byte, error) { return nil, nil }
	recovered, err = slice6RecoverVaultContainerWithDocker(context.Background(), run, name, missing)
	if err != nil || recovered != "" {
		t.Fatalf("absent exact create result should remain unproved, not fabricate ID: %q %v", recovered, err)
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

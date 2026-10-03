//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6StoredImage struct {
	name    string
	binding phase6profilebuilder.ImageBinding
}

// Docker canonicalizes Docker Hub names and drops a tag when storing a
// repository digest. This is only a name normalization; the digest must stay
// byte-for-byte identical and the requested full ref must resolve by inspect.
func slice6SameCanonicalRepoDigest(expected, observed string) bool {
	canonical := func(value string) string {
		parts := strings.Split(value, "@")
		if len(parts) != 2 || len(parts[1]) != len("sha256:")+64 ||
			!strings.HasPrefix(parts[1], "sha256:") || !lowerHexSlice6(strings.TrimPrefix(parts[1], "sha256:")) {
			return ""
		}
		repository := parts[0]
		lastSlash := strings.LastIndex(repository, "/")
		if colon := strings.LastIndex(repository, ":"); colon > lastSlash {
			repository = repository[:colon]
		}
		if strings.HasPrefix(repository, "docker.io/") {
			repository = strings.TrimPrefix(repository, "docker.io/")
		} else if strings.Contains(strings.Split(repository, "/")[0], ".") ||
			strings.Contains(strings.Split(repository, "/")[0], ":") {
			return repository + "@" + parts[1]
		}
		if !strings.Contains(repository, "/") {
			repository = "library/" + repository
		}
		return "docker.io/" + repository + "@" + parts[1]
	}
	left, right := canonical(expected), canonical(observed)
	return left != "" && left == right
}

// The source/OCI preflight proves bytes on disk, not that --pull=never can
// resolve the exact references used by the live Docker run. Keep this check
// before creating any network, container or issuer material.
func slice6VaultRequiredStoredImages(external phase6profilebuilder.ExternalImageSupply,
	images phase6profilebuilder.ImageSupply) ([]slice6StoredImage, error) {
	bindings := external.Bindings()
	result := make([]slice6StoredImage, 0, len(images.LocalRoleTargets)+7)
	for _, name := range []string{"vault", "postgres", "capacity-valkey", "dns"} {
		binding, ok := bindings[name]
		if !ok {
			return nil, errors.New("incomplete fixed external Docker image inventory")
		}
		result = append(result, slice6StoredImage{name, binding})
	}
	if images.Desktop.Reference == "" || images.Browser.Reference == "" || len(images.LocalRoleTargets) == 0 {
		return nil, errors.New("incomplete fixed role Docker image inventory")
	}
	result = append(result, slice6StoredImage{"desktop", images.Desktop},
		slice6StoredImage{"browser", images.Browser})
	for name, binding := range images.LocalRoleTargets {
		result = append(result, slice6StoredImage{name, binding})
	}
	slices.SortFunc(result, func(a, b slice6StoredImage) int { return strings.Compare(a.name, b.name) })
	return result, nil
}

func slice6VaultPreflightStoredImages(ctx context.Context, external phase6profilebuilder.ExternalImageSupply,
	images phase6profilebuilder.ImageSupply) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Docker image preflight context unavailable")
	}
	if _, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Output(); err != nil {
		return errors.New("Docker daemon unavailable before issuer allocation")
	}
	items, err := slice6VaultRequiredStoredImages(external, images)
	if err != nil {
		return err
	}
	err = slice6CheckStoredImages(ctx, items, images.RuntimeRevision, func(ctx context.Context, reference string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", "image", "inspect", reference).Output()
	})
	if err != nil {
		if _, daemonErr := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Output(); daemonErr != nil {
			return errors.New("Docker daemon unavailable during fixed image inventory")
		}
	}
	return err
}

func slice6VaultPreflightAllStoredImages(ctx context.Context, external phase6profilebuilder.ExternalImageSupply,
	images phase6profilebuilder.ImageSupply) error {
	// Collect both inventories before rejecting; a missing external reference
	// must not conceal a missing auxiliary image until the next issuer run.
	storedErr := slice6VaultPreflightStoredImages(ctx, external, images)
	auxiliaryErr := slice6PreflightAuxiliaryImages(ctx)
	if (storedErr != nil || auxiliaryErr != nil) && ctx != nil {
		if _, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Output(); err != nil {
			return errors.New("Docker daemon unavailable during complete fixed image inventory")
		}
	}
	return errors.Join(storedErr, auxiliaryErr)
}

func slice6CheckStoredImages(ctx context.Context, items []slice6StoredImage, sourceRevision string,
	inspect func(context.Context, string) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || len(items) == 0 || inspect == nil {
		return errors.New("fixed Docker image inventory unavailable")
	}
	seen := make(map[string][]byte, len(items))
	missing := make([]string, 0)
	mismatch := make([]string, 0)
	for _, item := range items {
		if item.name == "" || item.binding.Reference == "" || ctx.Err() != nil {
			return errors.New("fixed Docker image inventory changed")
		}
		document, ok := seen[item.binding.Reference]
		if !ok {
			var err error
			document, err = inspect(ctx, item.binding.Reference)
			if err != nil {
				missing = append(missing, item.name)
				seen[item.binding.Reference] = nil
				continue
			}
			seen[item.binding.Reference] = document
		}
		if document == nil {
			missing = append(missing, item.name)
			continue
		}
		principal := phase6security.Principal{Name: item.name, ImageReference: item.binding.Reference,
			ImageDigest: item.binding.Digest, ImageLocation: item.binding.Location,
			ImageIdentityKind: item.binding.Kind, ImagePlatform: item.binding.Platform,
			ImageSelectedManifestDigest: item.binding.SelectedManifestDigest,
			ImageConfigDigest:           item.binding.ConfigDigest}
		roleMismatch := false
		if item.binding.Location == "local" && item.name != "desktop" {
			deployment := slice6DeploymentForImageTarget(item.name)
			if deployment == "" {
				roleMismatch = true
			} else {
				principal.Name = deployment
				roleMismatch = phase6security.VerifySlice6LocalRoleImageInspect(principal, sourceRevision, document) != nil
			}
		}
		if verifyLoadedSlice6Image(principal, document) != nil || roleMismatch {
			mismatch = append(mismatch, item.name)
		}
	}
	if len(missing) != 0 || len(mismatch) != 0 {
		return fmt.Errorf("fixed Docker images unavailable before create: missing=%v identity_mismatch=%v", missing, mismatch)
	}
	return nil
}

func slice6DeploymentForImageTarget(target string) string {
	for _, deployment := range phase6security.Slice6DesiredDeploymentNames() {
		name, err := phase6security.Slice6DesiredImageTarget(deployment)
		if err == nil && name == target {
			return deployment
		}
	}
	return ""
}

type slice6AuxiliaryImage struct {
	name, reference, digest string
	registry                bool
}

// These are the current live harness's non-deployment create/run references:
// volume/SQL/terminal/observer Alpine, network diagnostics, and the eight
// finite break-glass tasks' shared carrier. The last reference comes from
// the locked Profile authority, not the selected manifest or a mutable tag.
func slice6RequiredAuxiliaryImages() []slice6AuxiliaryImage {
	return []slice6AuxiliaryImage{
		{"alpine-prep-terminal-observer", slice6PinnedAlpineImage,
			"sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c", true},
		{"network-probe", slice6NetworkProbeImageID, slice6NetworkProbeImageID, false},
		{"break-glass-operator-task", "docker.io/library/alpine@" + phase6security.Slice6BreakGlassCarrierIndexDigest,
			phase6security.Slice6BreakGlassCarrierIndexDigest, true},
	}
}

func slice6VerifyComposedTaskCarrier(profile phase6security.Profile) error {
	carrier := slice6RequiredAuxiliaryImages()[2]
	artifact := profile.BreakGlassExecutableArtifact
	if phase6security.VerifySlice6BreakGlassExecutableArtifact(profile) != nil ||
		artifact.CarrierReference != carrier.reference || artifact.CarrierIndexDigest != carrier.digest ||
		artifact.CarrierSelectedManifestDigest != phase6security.Slice6BreakGlassCarrierManifestDigest ||
		artifact.CarrierConfigDigest != phase6security.Slice6BreakGlassCarrierConfigDigest ||
		len(profile.BreakGlassOperatorTasks) != 8 {
		return errors.New("composed break-glass carrier differs from preissuer Docker admission")
	}
	for _, task := range profile.BreakGlassOperatorTasks {
		if task.ImageReference != carrier.reference {
			return errors.New("finite break-glass task image differs from admitted carrier")
		}
	}
	return nil
}

func slice6PreflightAuxiliaryImages(ctx context.Context) error {
	return slice6PreflightAuxiliaryImagesWithInspect(ctx, slice6RequiredAuxiliaryImages(),
		func(ctx context.Context, reference string) ([]byte, error) {
			return exec.CommandContext(ctx, "docker", "image", "inspect", reference).Output()
		})
}

func slice6PreflightAuxiliaryImagesWithInspect(ctx context.Context, items []slice6AuxiliaryImage,
	inspect func(context.Context, string) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("fixed auxiliary Docker image context unavailable")
	}
	if len(items) == 0 || inspect == nil {
		return errors.New("fixed auxiliary Docker image inventory unavailable")
	}
	missing := make([]string, 0)
	mismatch := make([]string, 0)
	for _, item := range items {
		if item.name == "" || item.reference == "" || item.digest == "" || ctx.Err() != nil {
			return errors.New("fixed auxiliary Docker image inventory changed")
		}
		document, err := inspect(ctx, item.reference)
		var images []struct {
			ID           string   `json:"Id"`
			OS           string   `json:"Os"`
			Architecture string   `json:"Architecture"`
			RepoDigests  []string `json:"RepoDigests"`
			Descriptor   *struct {
				Digest string `json:"digest"`
			} `json:"Descriptor"`
		}
		if err != nil {
			missing = append(missing, item.name)
			continue
		}
		if len(document) == 0 || len(document) > 2<<20 || json.Unmarshal(document, &images) != nil ||
			len(images) != 1 || images[0].ID != item.digest || images[0].OS != "linux" ||
			images[0].Architecture != "arm64" ||
			(item.registry &&
				(!slice6HasRepoDigest(images[0].RepoDigests, item.reference) ||
					images[0].Descriptor == nil || images[0].Descriptor.Digest != item.digest)) {
			mismatch = append(mismatch, item.name)
		}
	}
	if len(missing) != 0 || len(mismatch) != 0 {
		return fmt.Errorf("fixed auxiliary Docker images unavailable before create: missing=%v identity_mismatch=%v", missing, mismatch)
	}
	return nil
}

func slice6HasRepoDigest(digests []string, reference string) bool {
	for _, digest := range digests {
		if slice6SameCanonicalRepoDigest(reference, digest) {
			return true
		}
	}
	return false
}

package phase6security

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
)

// VerifySlice6LocalRoleImageInspect is a strict, reusable preflight check for
// the source-bound local role build, not proof of its archive or running
// container. Browser and Desktop sandbox images have separate authorities.
func VerifySlice6LocalRoleImageInspect(principal Principal, sourceRevision string, document []byte) error {
	target, err := Slice6DesiredImageTarget(principal.Name)
	if err != nil || target == Slice6BrowserPublishedImage || target == Slice6DesktopCandidateImage ||
		principal.ImageLocation != "local" || principal.ImageReference != principal.ImageDigest ||
		principal.ImageIdentityKind == ImageIdentityLocalConfig ||
		!validImageIdentity(principal.ImageLocation, principal.ImageIdentityKind,
			principal.ImageReference, principal.ImageDigest, principal.ImagePlatform,
			principal.ImageSelectedManifestDigest, principal.ImageConfigDigest) ||
		!slice6RevisionPattern.MatchString(sourceRevision) || len(sourceRevision) != 40 ||
		len(document) < 1 || len(document) > 2<<20 || rejectDuplicateMembers(document) != nil {
		return errors.New("Slice 6 local role image inspection is invalid")
	}
	var images []struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Variant      string `json:"Variant"`
		Descriptor   *struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"Descriptor"`
		Config struct {
			User       string            `json:"User"`
			Entrypoint []string          `json:"Entrypoint"`
			Cmd        []string          `json:"Cmd"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	expectedEntrypoint := []string{phase6fdloader.RolePath}
	if _, needsLoader := phase6fdloader.SpecificationFor(target); needsLoader {
		expectedEntrypoint = []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}
	}
	if json.Unmarshal(document, &images) != nil || len(images) != 1 ||
		images[0].ID != principal.ImageDigest ||
		!sameImagePlatform(images[0].OS, images[0].Architecture, images[0].Variant, principal.ImagePlatform) ||
		images[0].Descriptor == nil || images[0].Descriptor.Digest != principal.ImageDigest ||
		!validStoreDescriptorMediaType(principal.ImageIdentityKind, images[0].Descriptor.MediaType) ||
		images[0].Config.User != "65532:65532" ||
		len(images[0].Config.Cmd) != 0 || !slices.Equal(images[0].Config.Entrypoint, expectedEntrypoint) {
		return errors.New("Slice 6 local role image identity differs from profile")
	}
	labels := images[0].Config.Labels
	if labels["io.github.shell-echo.sandbox-runtime.phase6-candidate"] != "local-only-non-release" ||
		labels["io.github.shell-echo.sandbox-runtime.source-revision"] != sourceRevision ||
		labels["io.github.shell-echo.sandbox-runtime.role-target"] != target ||
		labels["io.github.shell-echo.sandbox-runtime.go-version"] != "go1.26.8" {
		return errors.New("Slice 6 local role image labels differ from source target")
	}
	return nil
}

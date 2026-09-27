// Package phase6slice6admission composes independently verified local image
// candidates with the neutral Slice 6 receipt bundle. It is not a substitute
// for a trusted live gate that establishes the origin of its observations.
package phase6slice6admission

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidAdmission = errors.New("invalid Phase 6 Slice 6 artifact admission")

// CandidateInputs are private operator-owned paths, never stable API fields.
type CandidateInputs struct {
	SourceRoot           string
	RoleCandidateDir     string
	DesktopCandidatePath string
	ManifestPath         string
	BundleRoot           string
}

// Verify is the complete offline admission entry point. A trusted live gate
// must still establish that the retained private raw bytes came from the
// named processes; passing this verifier alone is not execution provenance.
func Verify(ctx context.Context, inputs CandidateInputs) (phase6security.Slice6Evidence, error) {
	if !absolutePath(inputs.BundleRoot) || inputs.ManifestPath != filepath.Join(inputs.BundleRoot, "manifest.json") {
		return phase6security.Slice6Evidence{}, ErrInvalidAdmission
	}
	evidence, err := phase6security.VerifySlice6EvidenceBundle(inputs.ManifestPath, inputs.BundleRoot)
	if err != nil {
		return phase6security.Slice6Evidence{}, ErrInvalidAdmission
	}
	roles, desktop, err := verifyCandidateArtifacts(ctx, evidence, inputs)
	if err != nil || verifyDescriptorChain(evidence, inputs, roles, desktop) != nil {
		return phase6security.Slice6Evidence{}, ErrInvalidAdmission
	}
	return evidence, nil
}

// VerifyCandidateArtifacts reopens the exact private OCI archives and their
// typed manifests, then rederives their source from a clean checkout. A
// successful return establishes artifact identity only, not execution origin.
func VerifyCandidateArtifacts(ctx context.Context, evidence phase6security.Slice6Evidence, inputs CandidateInputs) error {
	_, _, err := verifyCandidateArtifacts(ctx, evidence, inputs)
	return err
}

func verifyCandidateArtifacts(ctx context.Context, evidence phase6security.Slice6Evidence,
	inputs CandidateInputs) ([]phase6rolecandidate.VerifiedArtifact, desktopcandidate.Manifest, error) {
	if ctx == nil || ctx.Err() != nil || evidence.Validate() != nil ||
		!absolutePath(inputs.SourceRoot) || !absolutePath(inputs.RoleCandidateDir) ||
		!absolutePath(inputs.DesktopCandidatePath) ||
		verifySource(ctx, inputs.SourceRoot, evidence.RuntimeRevision, evidence.RuntimeTreeDigest) != nil ||
		verifyReviewedProfile(evidence.Profile) != nil {
		return nil, desktopcandidate.Manifest{}, ErrInvalidAdmission
	}
	roles, err := phase6rolecandidate.VerifyDirectoryArtifacts(ctx, inputs.SourceRoot,
		inputs.RoleCandidateDir, evidence.Profile, evidence.RuntimeRevision)
	if err != nil {
		return nil, desktopcandidate.Manifest{}, ErrInvalidAdmission
	}
	desktop, err := desktopcandidate.LoadCurrent(inputs.DesktopCandidatePath)
	if err != nil || desktop.VerifySource(inputs.SourceRoot) != nil ||
		desktop.SourceRevision != evidence.RuntimeRevision ||
		desktop.SourceTreeDigest != evidence.RuntimeTreeDigest {
		return nil, desktopcandidate.Manifest{}, ErrInvalidAdmission
	}
	manifests := make([]phase6rolecandidate.Manifest, 0, len(roles))
	for _, artifact := range roles {
		manifests = append(manifests, artifact.Manifest)
	}
	if matchCandidates(evidence, manifests, desktop) != nil {
		return nil, desktopcandidate.Manifest{}, ErrInvalidAdmission
	}
	return roles, desktop, nil
}

func verifyDescriptorChain(evidence phase6security.Slice6Evidence, inputs CandidateInputs,
	roles []phase6rolecandidate.VerifiedArtifact, desktop desktopcandidate.Manifest) error {
	keys := make([]string, 0, (len(evidence.Profile.Principals)+len(evidence.Profile.External))*3)
	for _, principal := range evidence.Profile.Principals {
		prefix := "container/" + principal.Name + "/"
		keys = append(keys, prefix+"descriptor", prefix+"inspect", prefix+"image_inspect")
	}
	for _, external := range evidence.Profile.External {
		prefix := "external/" + external.Name + "/"
		keys = append(keys, prefix+"descriptor", prefix+"inspect", prefix+"image_inspect")
	}
	raw, err := phase6security.ReadSlice6RunReceipts(inputs.BundleRoot, evidence, keys)
	if err != nil {
		return ErrInvalidAdmission
	}
	archiveDocs := make(map[string]phase6security.ImageDescriptorDocuments, len(roles)+1)
	for _, role := range roles {
		manifest := role.Manifest
		documents, err := phase6security.ReadOCIArchiveDocuments(role.ManifestPath+".oci.tar",
			manifest.ImageIdentityKind, manifest.RuntimeStoreImageID,
			manifest.SelectedManifestDescriptor.Digest, manifest.OCIConfigDigest)
		if err != nil {
			return ErrInvalidAdmission
		}
		archiveDocs[manifest.RuntimeStoreImageID+"/"+manifest.Source.Platform] = documents
	}
	desktopDocuments, err := phase6security.ReadOCIArchiveDocuments(inputs.DesktopCandidatePath+".oci.tar",
		desktop.ImageIdentityKind, desktop.ImageDigest, desktop.SelectedManifestDigest, desktop.ConfigDigest)
	if err != nil {
		return ErrInvalidAdmission
	}
	archiveDocs[desktop.ImageDigest+"/"+desktop.Platform] = desktopDocuments
	observed := make(map[string]phase6security.ContainerObservation, len(evidence.Observations.Containers))
	for _, value := range evidence.Observations.Containers {
		observed[value.DeploymentName] = value
	}
	for _, principal := range evidence.Profile.Principals {
		prefix := "container/" + principal.Name + "/"
		documents, err := verifiedPayload(raw[prefix+"descriptor"], "container", principal.Name,
			principal.ImageLocation, principal.ImageIdentityKind, principal.ImageReference, principal.ImageDigest,
			principal.ImagePlatform, principal.ImageSelectedManifestDigest, principal.ImageConfigDigest,
			observed[principal.Name].ImageDescriptorProofDigest)
		if err != nil {
			return ErrInvalidAdmission
		}
		if principal.ImageLocation == "local" && !sameDocuments(documents, archiveDocs[principal.ImageDigest+"/"+principal.ImagePlatform]) {
			return ErrInvalidAdmission
		}
		image, err := phase6security.ObserveDockerRuntimeImage(raw[prefix+"inspect"], raw[prefix+"image_inspect"],
			principal.ImageLocation, principal.ImageIdentityKind, principal.ImageReference, principal.ImageDigest,
			principal.ImagePlatform, principal.ImageSelectedManifestDigest, principal.ImageConfigDigest, documents)
		observation := observed[principal.Name]
		if err != nil || image.ContainerID != observation.ContainerID ||
			image.ImageReference != observation.ImageReference || image.RuntimeStoreImageID != observation.RuntimeStoreImageID ||
			image.RuntimeStoreDescriptor != observation.RuntimeStoreDescriptor ||
			image.SelectedManifestDescriptor != observation.SelectedManifestDescriptor ||
			image.OCIConfigDigest != observation.OCIConfigDigest || image.RuntimePlatform != observation.RuntimePlatform ||
			image.DescriptorProofDigest != observation.ImageDescriptorProofDigest ||
			image.ContainerInspectDigest != observation.ContainerInspectDigest ||
			image.ImageInspectDigest != observation.ImageInspectDigest {
			return ErrInvalidAdmission
		}
	}
	for index, external := range evidence.Profile.External {
		prefix := "external/" + external.Name + "/"
		value := evidence.External[index]
		documents, err := verifiedPayload(raw[prefix+"descriptor"], "external", external.Name,
			external.ImageLocation, external.ImageIdentityKind, external.ImageReference, external.ImageDigest,
			external.ImagePlatform, external.ImageSelectedManifestDigest, external.ImageConfigDigest,
			value.DescriptorProofDigest)
		if err != nil {
			return ErrInvalidAdmission
		}
		image, err := phase6security.ObserveDockerRuntimeImage(raw[prefix+"inspect"], raw[prefix+"image_inspect"],
			external.ImageLocation, external.ImageIdentityKind, external.ImageReference, external.ImageDigest,
			external.ImagePlatform, external.ImageSelectedManifestDigest, external.ImageConfigDigest, documents)
		if err != nil || image.ContainerID != value.ContainerID || image.ImageReference != value.ImageReference ||
			image.RuntimeStoreImageID != value.RuntimeStoreImageID ||
			image.RuntimeStoreDescriptor != value.RuntimeStoreDescriptor ||
			image.SelectedManifestDescriptor != value.SelectedManifestDescriptor ||
			image.OCIConfigDigest != value.OCIConfigDigest || image.RuntimePlatform != value.RuntimePlatform ||
			image.DescriptorProofDigest != value.DescriptorProofDigest ||
			image.ContainerInspectDigest != value.ContainerInspectDigest || image.ImageInspectDigest != value.ImageInspectDigest {
			return ErrInvalidAdmission
		}
	}
	return nil
}

func verifiedPayload(raw []byte, kind, subject, location, identityKind, reference, digest, platform,
	selected, config, expectedProof string) (phase6security.ImageDescriptorDocuments, error) {
	payload, err := phase6security.DecodeSlice6DescriptorPayload(raw)
	if err != nil || payload.Kind != kind || payload.Subject != subject {
		return phase6security.ImageDescriptorDocuments{}, ErrInvalidAdmission
	}
	documents := payload.Documents()
	proof, err := phase6security.VerifyImageDescriptorDocuments(location, identityKind, reference,
		digest, platform, selected, config, documents)
	if err != nil || proof.ProofDigest != expectedProof || proof.ConfigDigest != config {
		return phase6security.ImageDescriptorDocuments{}, ErrInvalidAdmission
	}
	return documents, nil
}

func sameDocuments(left, right phase6security.ImageDescriptorDocuments) bool {
	return bytes.Equal(left.Index, right.Index) && bytes.Equal(left.Manifest, right.Manifest) && bytes.Equal(left.Config, right.Config)
}

func matchCandidates(evidence phase6security.Slice6Evidence, roles []phase6rolecandidate.Manifest,
	desktop desktopcandidate.Manifest) error {
	want := make([]phase6security.Slice6CandidateImage, 0, len(roles)+1)
	for _, role := range roles {
		want = append(want, role.CandidateEvidence())
	}
	want = append(want, desktop.CandidateEvidence())
	sort.Slice(want, func(i, j int) bool {
		return candidateKey(want[i]) < candidateKey(want[j])
	})
	if !reflect.DeepEqual(want, evidence.Candidates) {
		return ErrInvalidAdmission
	}
	for _, principal := range evidence.Profile.Principals {
		if principal.Name != "desktop-sandbox-runtime" {
			continue
		}
		if principal.ImageLocation != "local" || principal.ImageDigest != desktop.ImageDigest ||
			principal.ImagePlatform != desktop.Platform || principal.ImageIdentityKind != desktop.ImageIdentityKind ||
			principal.ImageConfigDigest != desktop.ConfigDigest ||
			principal.ImageSelectedManifestDigest != selectedProfileManifest(desktop.ImageIdentityKind, desktop.SelectedManifestDigest) {
			return ErrInvalidAdmission
		}
		return nil
	}
	return ErrInvalidAdmission
}

func candidateKey(value phase6security.Slice6CandidateImage) string {
	return value.RuntimeStoreImageID + "/" + value.Platform
}

func selectedProfileManifest(kind, digest string) string {
	if kind == phase6security.ImageIdentityOCIIndex {
		return digest
	}
	return ""
}

func verifySource(ctx context.Context, root, revision, tree string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidAdmission
	}
	status, err := exec.CommandContext(ctx, "git", "-C", root, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil || len(status) != 0 {
		return ErrInvalidAdmission
	}
	head, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(head)) != revision {
		return ErrInvalidAdmission
	}
	observed, err := desktopcandidate.SourceTreeDigest(root)
	if err != nil || observed != tree {
		return ErrInvalidAdmission
	}
	committed, err := desktopcandidate.SourceTreeDigestAtRevision(root, revision)
	if err != nil || committed != tree {
		return ErrInvalidAdmission
	}
	return nil
}

func verifyReviewedProfile(profile phase6security.Profile) error {
	for _, verify := range []func(phase6security.Profile) error{
		phase6security.VerifySlice6DesiredNetworks,
		phase6security.VerifySlice6DesiredPrincipalIDs,
		phase6security.VerifySlice6DesiredEdgeAddresses,
		phase6security.VerifySlice6DesiredExternalServices,
		phase6security.VerifySlice6DesiredEgressPolicies,
		phase6security.VerifySlice6DesiredTrustAnchors,
		phase6security.VerifySlice6DesiredTLSIdentities,
		phase6security.VerifySlice6DesiredImageLocations,
		phase6security.VerifySlice6DesiredIngress,
	} {
		if verify(profile) != nil {
			return ErrInvalidAdmission
		}
	}
	return nil
}

func absolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator)
}

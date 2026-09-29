package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidResourceSeccompSupply = errors.New("invalid Phase 6 resource/seccomp supply")

const resourceSeccompSchema = "sandbox-runtime.phase6-resource-seccomp.v1"

type dutyClassPolicy struct {
	ID              string                   `json:"id"`
	PolicyFile      string                   `json:"policy_file"`
	PolicyDigest    string                   `json:"policy_digest"`
	OriginalFile    string                   `json:"original_file"`
	OriginalDigest  string                   `json:"original_digest"`
	SourceURL       string                   `json:"source_url"`
	SourceRevision  string                   `json:"source_revision"`
	ChangeRationale string                   `json:"change_rationale"`
	LicenseFile     string                   `json:"license_file"`
	LicenseDigest   string                   `json:"license_digest"`
	Architectures   []string                 `json:"architectures"`
	Resources       phase6security.Resources `json:"resources"`
}

type dutyAssignment struct {
	Deployment string `json:"deployment"`
	DutyClass  string `json:"duty_class"`
}

type externalResourceLimit struct {
	Service   string                   `json:"service"`
	Resources phase6security.Resources `json:"resources"`
}

type resourceSeccompManifest struct {
	SchemaVersion string                  `json:"schema_version"`
	Platform      string                  `json:"platform"`
	Classes       []dutyClassPolicy       `json:"classes"`
	Assignments   []dutyAssignment        `json:"assignments"`
	External      []externalResourceLimit `json:"external"`
}

// ResourceSeccompSupply holds only checked original repository files. Its
// unexported fields prevent a caller from injecting a deployment policy map.
// It is still desired configuration, not observed Docker application or a
// measured release-tier claim.
type ResourceSeccompSupply struct {
	platform       string
	manifestDigest string
	classes        map[string]dutyClassPolicy
	assignments    map[string]string
	external       map[string]phase6security.Resources
	policyBytes    map[string][]byte
}

// ResourceDraft carries expected principal fields and arithmetic for the
// future gate's host admission check. It is not a complete security profile.
type ResourceDraft struct {
	PrincipalDraft
	Supply  ResourceSeccompSupply
	Budgets []phase6security.Slice6ResourceBudget
}

// BuildSlice6ResourceDraft is the source-bound builder chain up through image,
// duty-specific seccomp and finite resource policy. Until reviewed native
// manifest bytes exist, it intentionally cannot produce a draft.
func BuildSlice6ResourceDraft(ctx context.Context, input ImageDraftInputs) (ResourceDraft, error) {
	images, err := BuildSlice6ImageDraft(ctx, input)
	if err != nil {
		return ResourceDraft{}, err
	}
	if len(images.Principals) == 0 {
		return ResourceDraft{}, ErrInvalidResourceSeccompSupply
	}
	supply, err := LoadResourceSeccompSupply(input.SourceRoot, images.Principals[0].ImagePlatform)
	if err != nil {
		return ResourceDraft{}, err
	}
	bound, budgets, err := supply.BindResourceSeccompDraft(images)
	if err != nil {
		return ResourceDraft{}, err
	}
	return ResourceDraft{PrincipalDraft: bound, Supply: supply, Budgets: budgets}, nil
}

// Slice6ResourceSeccompManifestPath fixes the sole source path for one native
// platform. A missing manifest is a hard failure, not permission to inherit
// Docker runtime-default or an operator-provided limit.
func Slice6ResourceSeccompManifestPath(platform string) (string, error) {
	switch platform {
	case "linux/amd64":
		return "profiles/phase6/security/policy-amd64.json", nil
	case "linux/arm64/v8":
		return "profiles/phase6/security/policy-arm64.json", nil
	default:
		return "", ErrInvalidResourceSeccompSupply
	}
}

// LoadResourceSeccompSupply reopens the repository-owned manifest, original
// JSON, applied JSON and license bytes. Every duty and deployment must be
// explicitly present and match the independent reviewed inventory. No policy
// file in the current checkout means Slice 6 remains unlaunchable.
func LoadResourceSeccompSupply(sourceRoot, platform string) (ResourceSeccompSupply, error) {
	manifestPath, err := Slice6ResourceSeccompManifestPath(platform)
	if err != nil || !cleanAbsolute(sourceRoot) {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	manifestBytes, _, err := readSlice6RepositoryFile(sourceRoot, manifestPath, 256<<10)
	if err != nil {
		return ResourceSeccompSupply{}, err
	}
	var manifest resourceSeccompManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, manifestBytes) || manifest.SchemaVersion != resourceSeccompSchema ||
		manifest.Platform != platform {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	wantedClasses, err := phase6security.Slice6DesiredDutyClasses()
	if err != nil || len(manifest.Classes) != len(wantedClasses) {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	supply := ResourceSeccompSupply{platform: platform,
		manifestDigest: digestSlice6Bytes(manifestBytes),
		classes:        make(map[string]dutyClassPolicy, len(wantedClasses)),
		assignments:    make(map[string]string, len(manifest.Assignments)),
		external:       make(map[string]phase6security.Resources, len(manifest.External)),
		policyBytes:    make(map[string][]byte, len(wantedClasses))}
	for index, class := range manifest.Classes {
		if class.ID != wantedClasses[index] || !validSlice6SourceURL(class.SourceURL, class.SourceRevision) ||
			!validSlice6Architectures(class.Architectures, platform) ||
			!validImageDigest(class.PolicyDigest) || !validImageDigest(class.OriginalDigest) ||
			!validImageDigest(class.LicenseDigest) || len(class.ChangeRationale) > 2048 ||
			strings.ContainsAny(class.ChangeRationale, "\r\n\x00") ||
			((class.PolicyDigest != class.OriginalDigest || class.PolicyFile != class.OriginalFile) &&
				strings.TrimSpace(class.ChangeRationale) == "") {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		policyBytes, _, err := readSlice6RepositoryFile(sourceRoot, class.PolicyFile, 1<<20)
		if err != nil || digestSlice6Bytes(policyBytes) != class.PolicyDigest ||
			validateSlice6SeccompJSON(policyBytes, platform) != nil {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		originalBytes, _, err := readSlice6RepositoryFile(sourceRoot, class.OriginalFile, 1<<20)
		if err != nil || digestSlice6Bytes(originalBytes) != class.OriginalDigest ||
			validateSlice6SeccompJSON(originalBytes, platform) != nil {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		licenseBytes, _, err := readSlice6RepositoryFile(sourceRoot, class.LicenseFile, 256<<10)
		if err != nil || digestSlice6Bytes(licenseBytes) != class.LicenseDigest {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		supply.classes[class.ID] = class
		supply.policyBytes[class.ID] = bytes.Clone(policyBytes)
	}
	wantedDeployments := phase6security.Slice6DesiredDeploymentNames()
	if len(manifest.Assignments) != len(wantedDeployments) {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	usedClasses := make(map[string]bool, len(wantedClasses))
	principalLimits := make(map[string]phase6security.Resources, len(wantedDeployments))
	for index, assignment := range manifest.Assignments {
		wantedDuty, err := phase6security.Slice6DesiredDutyClass(wantedDeployments[index])
		if err != nil || assignment.Deployment != wantedDeployments[index] || assignment.DutyClass != wantedDuty {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		class, found := supply.classes[assignment.DutyClass]
		if !found {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		usedClasses[class.ID] = true
		supply.assignments[assignment.Deployment] = class.ID
		principalLimits[assignment.Deployment] = class.Resources
	}
	if len(usedClasses) != len(wantedClasses) {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	wantedExternal := phase6security.Slice6DesiredExternalServiceNames()
	if len(manifest.External) != len(wantedExternal) {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	for index, external := range manifest.External {
		if external.Service != wantedExternal[index] {
			return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
		}
		supply.external[external.Service] = external.Resources
	}
	if _, err := phase6security.CalculateSlice6ResourceBudgets(principalLimits, supply.external); err != nil {
		return ResourceSeccompSupply{}, ErrInvalidResourceSeccompSupply
	}
	return supply, nil
}

func (s ResourceSeccompSupply) ManifestDigest() string { return s.manifestDigest }

// SeccompPolicyJSON returns a copy of the bytes checked when the repository
// supply was loaded. A future Docker launcher must apply this exact snapshot
// through a private input and separately inspect the resulting container;
// returning the original repository path would reopen a check/use race.
func (s ResourceSeccompSupply) SeccompPolicyJSON(deployment string) ([]byte, string, error) {
	duty := s.assignments[deployment]
	class, found := s.classes[duty]
	policy := s.policyBytes[duty]
	if !found || len(policy) == 0 || digestSlice6Bytes(policy) != class.PolicyDigest {
		return nil, "", ErrInvalidResourceSeccompSupply
	}
	return bytes.Clone(policy), class.PolicyDigest, nil
}

// VerifyProfilePolicies binds every declared principal to the reviewed
// source manifest. It checks desired inputs only; the live gate must still
// inspect Docker's applied policy and cgroup/process observations.
func (s ResourceSeccompSupply) VerifyProfilePolicies(profile phase6security.Profile) error {
	if len(profile.Principals) != len(s.assignments) || len(s.classes) == 0 || s.manifestDigest == "" {
		return ErrInvalidResourceSeccompSupply
	}
	seen := make(map[string]bool, len(profile.Principals))
	for _, principal := range profile.Principals {
		duty, assigned := s.assignments[principal.Name]
		class, found := s.classes[duty]
		if !assigned || !found || seen[principal.Name] || principal.ImagePlatform != s.platform ||
			principal.SeccompDigest != class.PolicyDigest || principal.Resources != class.Resources {
			return ErrInvalidResourceSeccompSupply
		}
		if _, digest, err := s.SeccompPolicyJSON(principal.Name); err != nil || digest != principal.SeccompDigest {
			return ErrInvalidResourceSeccompSupply
		}
		seen[principal.Name] = true
	}
	return nil
}

// BindResourceSeccompDraft fills only the reviewed resource and seccomp
// fields, after exact image-platform binding. It refuses any prebound fields
// and returns lifecycle arithmetic for host admission planning, not approval.
func (s ResourceSeccompSupply) BindResourceSeccompDraft(draft PrincipalDraft) (PrincipalDraft,
	[]phase6security.Slice6ResourceBudget, error) {
	if len(draft.Principals) != len(s.assignments) || len(s.classes) == 0 || s.manifestDigest == "" {
		return PrincipalDraft{}, nil, ErrInvalidResourceSeccompSupply
	}
	bound := append([]phase6security.Principal(nil), draft.Principals...)
	limits := make(map[string]phase6security.Resources, len(bound))
	for index := range bound {
		principal := &bound[index]
		duty := s.assignments[principal.Name]
		class, found := s.classes[duty]
		if !found || principal.ImagePlatform != s.platform || principal.ImageDigest == "" ||
			principal.SeccompDigest != "" || principal.Resources != (phase6security.Resources{}) {
			return PrincipalDraft{}, nil, ErrInvalidResourceSeccompSupply
		}
		principal.SeccompDigest, principal.Resources = class.PolicyDigest, class.Resources
		limits[principal.Name] = class.Resources
	}
	budgets, err := phase6security.CalculateSlice6ResourceBudgets(limits, s.external)
	if err != nil {
		return PrincipalDraft{}, nil, ErrInvalidResourceSeccompSupply
	}
	return PrincipalDraft{Principals: bound, Networks: append([]phase6security.Network(nil), draft.Networks...),
		CredentialIssuerSockets: append([]phase6security.CredentialIssuerSocketBinding(nil), draft.CredentialIssuerSockets...)}, budgets, nil
}

func validSlice6Architectures(architectures []string, platform string) bool {
	if len(architectures) < 1 || len(architectures) > 2 || !slices.IsSorted(architectures) ||
		!slices.Contains(architectures, platform) {
		return false
	}
	for index, architecture := range architectures {
		if (architecture != "linux/amd64" && architecture != "linux/arm64/v8") ||
			(index > 0 && architectures[index-1] == architecture) {
			return false
		}
	}
	return true
}

func validSlice6SourceURL(value, revision string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && len(value) <= 1024 &&
		len(revision) == 40 && lowerHex(revision) && slices.Contains(strings.Split(parsed.Path, "/"), revision)
}

func digestSlice6Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", sum)
}

func readSlice6RepositoryFile(root, relative string, maximum int64) ([]byte, string, error) {
	if !cleanAbsolute(root) || !strings.HasPrefix(relative, "profiles/") ||
		strings.Contains(relative, "\\") || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return nil, "", ErrInvalidResourceSeccompSupply
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", ErrInvalidResourceSeccompSupply
	}
	current := root
	parts := strings.Split(relative, "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, "", ErrInvalidResourceSeccompSupply
		}
		current = filepath.Join(current, part)
		info, err = os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 ||
			(index < len(parts)-1 && !info.IsDir()) || (index == len(parts)-1 && !info.Mode().IsRegular()) {
			return nil, "", ErrInvalidResourceSeccompSupply
		}
	}
	if info.Size() < 1 || info.Size() > maximum {
		return nil, "", ErrInvalidResourceSeccompSupply
	}
	document, err := os.ReadFile(current)
	if err != nil || int64(len(document)) != info.Size() {
		return nil, "", ErrInvalidResourceSeccompSupply
	}
	return document, current, nil
}

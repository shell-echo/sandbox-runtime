package phase6profilebuilder

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const syntheticSeccomp = `{"defaultAction":"SCMP_ACT_ERRNO","archMap":[{"architecture":"SCMP_ARCH_AARCH64","subArchitectures":[]}],"syscalls":[{"names":["read","write"],"action":"SCMP_ACT_ALLOW","args":[],"comment":"","includes":{},"excludes":{}}]}`

func writeSyntheticResourceSupply(t *testing.T) (string, resourceSeccompManifest) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "profiles", "phase6", "security")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := []byte(syntheticSeccomp)
	license := []byte("Apache-2.0 synthetic parser fixture\n")
	if err := os.WriteFile(filepath.Join(directory, "synthetic.json"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "LICENSE.synthetic"), license, 0o600); err != nil {
		t.Fatal(err)
	}
	classes, err := phase6security.Slice6DesiredDutyClasses()
	if err != nil {
		t.Fatal(err)
	}
	manifest := resourceSeccompManifest{SchemaVersion: resourceSeccompSchema, Platform: "linux/arm64/v8"}
	// Identical tiny limits and policy bytes are parser fixtures only. The
	// actual arm64 candidate is separately checked below; no production
	// admission or live seccomp application can be inferred from this test.
	unit := phase6security.Resources{MemoryBytes: 16 << 20, CPUMillis: 10, PIDs: 4}
	for _, duty := range classes {
		manifest.Classes = append(manifest.Classes, dutyClassPolicy{ID: duty,
			PolicyFile: "profiles/phase6/security/synthetic.json", PolicyDigest: digestSlice6Bytes(policy),
			OriginalFile: "profiles/phase6/security/synthetic.json", OriginalDigest: digestSlice6Bytes(policy),
			SourceURL: "https://example.test/source/" + strings.Repeat("a", 40), SourceRevision: strings.Repeat("a", 40),
			LicenseFile: "profiles/phase6/security/LICENSE.synthetic", LicenseDigest: digestSlice6Bytes(license),
			Architectures: []string{"linux/arm64/v8"}, Resources: unit})
	}
	for _, deployment := range phase6security.Slice6DesiredDeploymentNames() {
		duty, err := phase6security.Slice6DesiredDutyClass(deployment)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Assignments = append(manifest.Assignments, dutyAssignment{Deployment: deployment, DutyClass: duty})
	}
	for _, service := range phase6security.Slice6DesiredExternalServiceNames() {
		manifest.External = append(manifest.External, externalResourceLimit{Service: service, Resources: unit})
	}
	writeSyntheticManifest(t, root, manifest)
	return root, manifest
}

func writeSyntheticManifest(t *testing.T, root string, manifest resourceSeccompManifest) {
	t.Helper()
	document, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path, err := Slice6ResourceSeccompManifestPath(manifest.Platform)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, path), document, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResourceSeccompSupplyBindsCompleteReviewedDuties(t *testing.T) {
	root, _ := writeSyntheticResourceSupply(t)
	supply, err := LoadResourceSeccompSupply(root, "linux/arm64/v8")
	if err != nil || supply.ManifestDigest() == "" {
		t.Fatalf("complete synthetic supply rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "profiles/phase6/security/synthetic.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	draft, err := BuildSlice6PrincipalDraft(strings.Repeat("c", 32),
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	for index := range draft.Principals {
		draft.Principals[index].ImagePlatform = "linux/arm64/v8"
		draft.Principals[index].ImageDigest = "sha256:" + strings.Repeat("d", 64)
	}
	bound, budgets, err := supply.BindResourceSeccompDraft(draft)
	if err != nil || len(bound.Principals) != 82 || len(budgets) != 6 ||
		!slices.Equal(bound.CredentialIssuerSockets, draft.CredentialIssuerSockets) {
		t.Fatalf("complete resource/seccomp draft rejected: %v", err)
	}
	for index, principal := range bound.Principals {
		if principal.Resources.MemoryBytes != 16<<20 || principal.SeccompDigest == "" ||
			draft.Principals[index].SeccompDigest != "" || draft.Principals[index].Resources != (phase6security.Resources{}) {
			t.Fatalf("resource binding mutated input or omitted %s", principal.Name)
		}
		policy, digest, err := supply.SeccompPolicyJSON(principal.Name)
		if err != nil || !slices.Equal(policy, []byte(syntheticSeccomp)) || digest != principal.SeccompDigest {
			t.Fatalf("immutable policy snapshot missing for %s: %v", principal.Name, err)
		}
		policy[0] = 'x'
		fresh, _, err := supply.SeccompPolicyJSON(principal.Name)
		if err != nil || !slices.Equal(fresh, []byte(syntheticSeccomp)) {
			t.Fatalf("caller mutated policy snapshot for %s", principal.Name)
		}
	}
	profile := phase6security.Profile{Principals: bound.Principals}
	if err := supply.VerifyProfilePolicies(profile); err != nil {
		t.Fatalf("complete source-bound policy profile rejected: %v", err)
	}
	for name, change := range map[string]func(*phase6security.Profile){
		"resource drift": func(value *phase6security.Profile) { value.Principals[0].Resources.PIDs++ },
		"seccomp drift": func(value *phase6security.Profile) {
			value.Principals[0].SeccompDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"platform drift": func(value *phase6security.Profile) { value.Principals[0].ImagePlatform = "linux/amd64" },
		"duplicate role": func(value *phase6security.Profile) { value.Principals[0].Name = value.Principals[1].Name },
		"missing role":   func(value *phase6security.Profile) { value.Principals = value.Principals[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := phase6security.Profile{Principals: append([]phase6security.Principal(nil), bound.Principals...)}
			change(&changed)
			if !errors.Is(supply.VerifyProfilePolicies(changed), ErrInvalidResourceSeccompSupply) {
				t.Fatal("drifted profile policy admitted")
			}
		})
	}
	prebound := draft
	prebound.Principals = append([]phase6security.Principal(nil), draft.Principals...)
	prebound.Principals[0].Resources = phase6security.Resources{MemoryBytes: 64 << 20}
	if _, _, err := supply.BindResourceSeccompDraft(prebound); !errors.Is(err, ErrInvalidResourceSeccompSupply) {
		t.Fatal("prebound resource policy was silently overwritten")
	}
}

func TestResourceSeccompSupplyRejectsMissingDriftedAndAmbiguousFiles(t *testing.T) {
	root, manifest := writeSyntheticResourceSupply(t)
	manifest.Classes[0].PolicyDigest = "sha256:" + strings.Repeat("0", 64)
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("seccomp digest drift admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	manifest.Assignments[0].DutyClass = "tls_agent"
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("deployment duty substitution admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	manifest.External = manifest.External[1:]
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("external resource omission admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	manifest.Classes[0].SourceRevision = strings.Repeat("b", 40)
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("mismatched source revision admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	original := []byte(strings.Replace(syntheticSeccomp, `"write"`, `"close"`, 1))
	if err := os.WriteFile(filepath.Join(root, "profiles/phase6/security/original.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest.Classes[0].OriginalFile = "profiles/phase6/security/original.json"
	manifest.Classes[0].OriginalDigest = digestSlice6Bytes(original)
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("derived policy without change rationale admitted")
	}
	manifest.Classes[0].ChangeRationale = "synthetic applied policy adds write in place of close"
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err != nil {
		t.Fatalf("explicitly explained synthetic derivation rejected: %v", err)
	}
	manifest.Classes[0].ChangeRationale = "  "
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("blank policy-change rationale admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	manifest.Classes[0].SourceURL += "-not-a-revision-segment"
	writeSyntheticManifest(t, root, manifest)
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("source URL with merely embedded revision admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	path := filepath.Join(root, manifest.Classes[0].PolicyFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, manifest.Classes[0].LicenseFile), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("symlinked seccomp file admitted")
	}
	root, manifest = writeSyntheticResourceSupply(t)
	manifestPath, _ := Slice6ResourceSeccompManifestPath(manifest.Platform)
	document, err := os.ReadFile(filepath.Join(root, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, manifestPath), append([]byte("\n"), document...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResourceSeccompSupply(root, manifest.Platform); err == nil {
		t.Fatal("noncanonical manifest admitted")
	}
}

func TestSlice6SeccompJSONRejectsUnsafeOrAmbiguousPolicy(t *testing.T) {
	if err := validateSlice6SeccompJSON([]byte(syntheticSeccomp), "linux/arm64/v8"); err != nil {
		t.Fatalf("closed synthetic policy rejected: %v", err)
	}
	boundedErrno := strings.Replace(syntheticSeccomp, `"action":"SCMP_ACT_ALLOW"`, `"action":"SCMP_ACT_ERRNO","errnoRet":38`, 1)
	if err := validateSlice6SeccompJSON([]byte(boundedErrno), "linux/arm64/v8"); err != nil {
		t.Fatalf("bounded explicit errno rule rejected: %v", err)
	}
	for _, document := range []string{
		strings.Replace(syntheticSeccomp, `SCMP_ACT_ERRNO`, `SCMP_ACT_ALLOW`, 1),
		strings.Replace(syntheticSeccomp, `"defaultAction":"SCMP_ACT_ERRNO"`, `"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":0`, 1),
		strings.Replace(syntheticSeccomp, `"action":"SCMP_ACT_ALLOW"`, `"action":"SCMP_ACT_ALLOW","errnoRet":38`, 1),
		strings.Replace(syntheticSeccomp, `SCMP_ARCH_AARCH64`, `SCMP_ARCH_X86_64`, 1),
		strings.Replace(syntheticSeccomp, `"defaultAction":"SCMP_ACT_ERRNO"`, `"defaultAction":"SCMP_ACT_ERRNO","defaultAction":"SCMP_ACT_ERRNO"`, 1),
		strings.Replace(syntheticSeccomp, `"names":["read","write"]`, `"names":["*"]`, 1),
	} {
		if err := validateSlice6SeccompJSON([]byte(document), "linux/arm64/v8"); err == nil {
			t.Fatal("unsafe or ambiguous seccomp JSON admitted")
		}
	}
}

func TestSlice6SeccompParserAcceptsExistingLockedBrowserPolicy(t *testing.T) {
	applied, err := os.ReadFile("../../profiles/browser/image/chromium-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("../../profiles/phase6/security/originals/playwright-seccomp-ae935a43.json")
	if err != nil {
		t.Fatal(err)
	}
	if digestSlice6Bytes(original) != "sha256:cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849" ||
		digestSlice6Bytes(applied) != "sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b" {
		t.Fatal("retained original or derived Browser policy drifted")
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64/v8"} {
		for _, document := range [][]byte{original, applied} {
			if err := validateSlice6SeccompJSON(document, platform); err != nil {
				t.Fatalf("retained original or applied Browser policy rejected on %s: %v", platform, err)
			}
		}
	}
}

func TestSlice6SeccompParserAcceptsPinnedMobyOriginal(t *testing.T) {
	document, err := os.ReadFile("../../profiles/phase6/security/originals/moby-default-seccomp-836ae4d3.json")
	if err != nil {
		t.Fatal(err)
	}
	license, err := os.ReadFile("../../profiles/phase6/security/originals/LICENSE.moby-profiles-836ae4d3")
	if err != nil {
		t.Fatal(err)
	}
	if digestSlice6Bytes(document) != "sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" ||
		digestSlice6Bytes(license) != "sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30" {
		t.Fatal("pinned Moby source or license drifted")
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64/v8"} {
		if err := validateSlice6SeccompJSON(document, platform); err != nil {
			t.Fatalf("pinned Moby original rejected on %s: %v", platform, err)
		}
	}
}

func TestSlice6RepositoryArm64CandidateResourceSupply(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	supply, err := LoadResourceSeccompSupply(root, "linux/arm64/v8")
	if err != nil {
		t.Fatalf("reviewed arm64 candidate supply rejected: %v", err)
	}
	if len(supply.classes) != 23 || len(supply.assignments) != 82 || len(supply.external) != 5 {
		t.Fatal("arm64 candidate does not cover the complete duty/deployment/service inventory")
	}
	if supply.classes["chromium_sandbox"].PolicyDigest !=
		"sha256:3bdf2fd28636409951409621735f616997d0fd4851259851ac4c340dff90e05b" ||
		supply.classes["desktop_x11_sandbox"].PolicyDigest !=
			"sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("sandbox duties lost their independently sourced candidate policy bytes")
	}
	for _, duty := range []string{"break_glass_controller", "certificate_controller", "credential_controller",
		"egress_policy_authority", "migration_material_agent", "runtime_material_agent", "tls_agent"} {
		class := supply.classes[duty]
		if class.PolicyDigest != "sha256:a7f79239f02d9326e74deb212d2022f4bb2db9e2316367e0d89c9e35f7893eaa" ||
			class.PolicyDigest == class.OriginalDigest {
			t.Fatalf("%s lacks the source-bound controller/agent policy derivation", duty)
		}
		var policy slice6SeccompDocument
		if err := json.Unmarshal(supply.policyBytes[duty], &policy); err != nil {
			t.Fatal(err)
		}
		clone3Fallback := false
		for _, rule := range policy.Syscalls {
			for _, name := range rule.Names {
				if rule.Action == "SCMP_ACT_ALLOW" && slices.Contains([]string{
					"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd", "process_madvise",
				}, name) {
					t.Fatalf("%s retains an allowed process-inspection syscall %s", duty, name)
				}
				if name == "clone3" && rule.Action == "SCMP_ACT_ERRNO" && rule.ErrnoRet != nil &&
					*rule.ErrnoRet == 38 {
					clone3Fallback = true
				}
			}
		}
		if !clone3Fallback {
			t.Fatalf("%s lost the Go thread-creation fallback", duty)
		}
	}
	limits := make(map[string]phase6security.Resources, len(supply.assignments))
	for deployment, duty := range supply.assignments {
		limits[deployment] = supply.classes[duty].Resources
	}
	budgets, err := phase6security.CalculateSlice6ResourceBudgets(limits, supply.external)
	if err != nil || len(budgets) != 6 {
		t.Fatalf("arm64 candidate lifecycle arithmetic rejected: %v", err)
	}
	if budgets[0].Envelope != "steady_without_sandboxes" ||
		budgets[0].MemoryBytes != 7680<<20 || budgets[0].CPUMillis != 7750 || budgets[0].PIDs != 2096 ||
		budgets[5].Envelope != "browser_desktop_active" ||
		budgets[5].MemoryBytes != 9216<<20 || budgets[5].CPUMillis != 9750 || budgets[5].PIDs != 2480 {
		t.Fatalf("arm64 candidate capacity arithmetic drifted: %#v", budgets)
	}
}

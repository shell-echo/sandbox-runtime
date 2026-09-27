package phase6security

import (
	"testing"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

func TestSlice6EveryDeploymentHasOneReviewedImageTarget(t *testing.T) {
	if len(slice6DesiredImageTargets) != 58 || len(slice6DesiredImageTargets) != len(slice6ApprovedDeploymentKinds) {
		t.Fatal("reviewed Slice 6 image-target inventory drifted")
	}
	allowed := map[string]bool{
		"core": true, "browser-action-ingress": true, "browser-executor-backend": true,
		"desktop-executor-backend": true, "workload-tls-agent": true, "workload-material-agent": true,
		"workload-credential-controller-v2": true, "break-glass-controller": true,
		"certificate-controller": true, "egress-policy-broker": true,
		"egress-policy-state-authority": true, "phase6-ingress-relay": true,
		Slice6BrowserPublishedImage: true, Slice6DesktopCandidateImage: true,
	}
	for name := range slice6ApprovedDeploymentKinds {
		target, err := Slice6DesiredImageTarget(name)
		if err != nil || !allowed[target] {
			t.Fatalf("approved deployment %s lacks a reviewed build target: %q, %v", name, target, err)
		}
	}
	if _, err := Slice6DesiredImageTarget("unreviewed-runtime"); err == nil {
		t.Fatal("unreviewed deployment acquired an image build target")
	}
}

func TestSlice6ImageLocationPlanRejectsRegistryRoleSubstitution(t *testing.T) {
	profile := reviewedSlice6ImageFixture(t)
	if err := profile.Validate(); err != nil {
		t.Fatalf("reviewed local image draft is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredImageLocations(profile); err != nil {
		t.Fatalf("reviewed image location plan rejected: %v", err)
	}
	profile.Principals[0].ImageLocation = "registry"
	profile.Principals[0].ImageReference = "registry.example.test/role@" + profile.Principals[0].ImageDigest
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("registry substitution fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredImageLocations(profile); err == nil {
		t.Fatal("self-consistent registry role substitution was admitted")
	}
	for name, mutate := range map[string]func(*Principal){
		"browser digest": func(p *Principal) {
			p.ImageDigest = testDigest("different-browser-index")
			p.ImageReference = "ghcr.io/shell-echo/sandbox-runtime-browser@" + p.ImageDigest
		},
		"browser repository": func(p *Principal) {
			p.ImageReference = "ghcr.io/other/browser@" + p.ImageDigest
		},
		"browser selected manifest": func(p *Principal) {
			p.ImageSelectedManifestDigest = testDigest("different-browser-manifest")
		},
		"browser platform": func(p *Principal) {
			p.ImagePlatform = "linux/amd64"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := reviewedSlice6ImageFixture(t)
			for index := range candidate.Principals {
				if candidate.Principals[index].Name == "browser-sandbox-runtime" {
					mutate(&candidate.Principals[index])
					refreshSlice6ImageSlotDigest(&candidate, candidate.Principals[index])
				}
			}
			candidate.ProfileDigest = candidate.Digest()
			if err := candidate.Validate(); err != nil {
				t.Fatalf("browser substitution fixture is not internally valid: %v", err)
			}
			if err := VerifySlice6DesiredImageLocations(candidate); err == nil {
				t.Fatal("self-consistent Browser publication substitution was admitted")
			}
		})
	}
}

func refreshSlice6ImageSlotDigest(profile *Profile, principal Principal) {
	for index := range profile.SandboxIdentitySlots {
		if profile.SandboxIdentitySlots[index].Template == principal.Name {
			profile.SandboxIdentitySlots[index].TemplateDigest = SandboxTemplateDigest(principal)
		}
	}
}

func reviewedSlice6ImageFixture(t *testing.T) Profile {
	t.Helper()
	profile := validProfile()
	profile.Principals = append([]Principal(nil), profile.Principals...)
	for index := range profile.Principals {
		principal := &profile.Principals[index]
		if principal.Name == "browser-sandbox-runtime" {
			principal.ImageReference = browserimage.LockedPublication().Image()
			principal.ImageDigest = browserimage.PublishedDigest
			principal.ImageIdentityKind = ImageIdentityOCIIndex
			principal.ImageSelectedManifestDigest = browserimage.PublishedARM64Manifest
			refreshSlice6ImageSlotDigest(&profile, *principal)
			continue
		}
		principal.ImageLocation = "local"
		principal.ImageReference = principal.ImageDigest
		if principal.Name == "desktop-sandbox-runtime" {
			refreshSlice6ImageSlotDigest(&profile, *principal)
		}
	}
	profile.ProfileDigest = profile.Digest()
	return profile
}

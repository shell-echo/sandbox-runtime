package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6BreakGlassExecutableArtifactClosesCarrierAndTwoMountTask(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	profile = bindSyntheticSlice6DNSClientCA(t, profile)
	if VerifySlice6BreakGlassExecutableArtifact(profile) != nil || VerifySlice6FinalGateProfile(profile) != nil {
		t.Fatal("synthetic artifact shape rejected")
	}
	for _, mutate := range []func(*Profile){
		func(p *Profile) { p.BreakGlassExecutableArtifact.BinaryDigest = "sha256:not-a-digest" },
		func(p *Profile) { p.BreakGlassExecutableArtifact.BinaryBytes = 0 },
		func(p *Profile) { p.BreakGlassExecutableArtifact.Toolchain = "go1.26.7" },
		func(p *Profile) { p.BreakGlassExecutableArtifact.ToolchainDigest = "sha256:bad" },
		func(p *Profile) { p.BreakGlassExecutableArtifact.SourceRevision = "unbound" },
		func(p *Profile) {
			p.BreakGlassExecutableArtifact.SourceRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		func(p *Profile) { p.BreakGlassExecutableArtifact.Platform = "linux/amd64" },
		func(p *Profile) { p.BreakGlassExecutableArtifact.CarrierIndexDigest = testDigest("different-index") },
		func(p *Profile) {
			p.BreakGlassExecutableArtifact.CarrierSelectedManifestDigest = testDigest("different-manifest")
		},
		func(p *Profile) { p.BreakGlassExecutableArtifact.CarrierConfigDigest = testDigest("different-config") },
		func(p *Profile) { p.BreakGlassOperatorTasks[0].ExecutableMount.ReadOnly = false },
		func(p *Profile) { p.BreakGlassOperatorTasks[0].ExecutableMount.Target = "/host/source" },
		func(p *Profile) { p.BreakGlassOperatorTasks[0].Mount.Target = "/run/phase6/break-glass" },
	} {
		changed := profile
		changed.BreakGlassOperatorTasks = slices.Clone(profile.BreakGlassOperatorTasks)
		mutate(&changed)
		changed.ProfileDigest = changed.Digest()
		if VerifySlice6BreakGlassExecutableArtifact(changed) == nil && VerifySlice6BreakGlassBoundaries(changed) == nil {
			t.Fatal("break-glass operator executable or mount drift admitted")
		}
	}
}

package phase6profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validArtifact() Artifact {
	digest := "sha256:" + strings.Repeat("a", 64)
	return Artifact{ImageReference: "registry.example.test/sandbox-runtime@" + digest, ImageDigest: digest, SBOMDigest: digest, ProvenanceDigest: digest, SignatureDigest: digest, Architectures: []string{"amd64", "arm64"}}
}

func validProfile() Profile {
	role := func(name, account string, public, outbound bool) Role {
		return Role{Name: name, ServiceAccount: account, Artifact: validArtifact(), LivenessPath: "/livez", ReadinessPath: "/readyz", PublicIngress: public, OutboundOnly: outbound}
	}
	profile := Profile{Version: 1, Revision: "phase6-revision", SourceDigest: "sha256:" + strings.Repeat("c", 64), Configuration: "sha256:" + strings.Repeat("b", 64), Roles: []Role{role("gateway", "gateway", true, false), role("guest", "guest", false, true), role("browser", "browser", false, false), role("desktop", "desktop", false, false)}}
	profile.ProfileDigest = profile.CanonicalDigest()
	return profile
}

func TestProfileValidatesRoleBoundariesAndImmutableArtifacts(t *testing.T) {
	profile := validProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	profile.ProfileDigest = "sha256:" + strings.Repeat("d", 64)
	if err := profile.Validate(); err == nil {
		t.Fatal("profile content digest mismatch was accepted")
	}
	profile.Roles[0].Artifact.ImageReference = "registry.example.test/sandbox-runtime:latest"
	if err := profile.Validate(); err == nil {
		t.Fatal("mutable image reference was accepted")
	}
}

func TestProfileRejectsSharedServiceAccounts(t *testing.T) {
	profile := validProfile()
	profile.Roles[1].ServiceAccount = profile.Roles[0].ServiceAccount
	if err := profile.Validate(); err == nil {
		t.Fatal("shared role service account was accepted")
	}
}

func TestVerifyFileRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "profile.json")
	contents, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(contents, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

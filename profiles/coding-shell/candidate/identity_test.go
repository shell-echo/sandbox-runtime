package candidate_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

func TestCandidateOriginalDescriptorIdentityBothPlatforms(t *testing.T) {
	for _, platform := range []string{"linux/arm64/v8", "linux/amd64"} {
		t.Run(platform, func(t *testing.T) {
			i, err := candidate.LockedIdentity(platform)
			if err != nil || i.GoVersion != "go1.26.9" || i.SourceCommit != "91fe315641779e6ea640632538309d63ad1b303f" || i.Status != "unsigned-local-held" {
				t.Fatal("locked input identity drift")
			}
			m, c, err := candidate.DescriptorDocuments(platform)
			if err != nil || i.ManifestSize != int64(len(m)) {
				t.Fatal("missing original descriptor")
			}
			proof, err := phase6security.VerifyImageDescriptorDocuments("local", phase6security.ImageIdentityOCIManifest, i.ManifestDigest, i.ManifestDigest, platform, "", i.ConfigDigest, phase6security.ImageDescriptorDocuments{Manifest: m, Config: c})
			if err != nil || proof.ConfigDigest != i.ConfigDigest || proof.ProofDigest == "" {
				t.Fatal("original descriptor chain rejected", err)
			}
			m[0], c[0] = 'x', 'x'
			m2, c2, err := candidate.DescriptorDocuments(platform)
			if err != nil || bytes.Equal(m, m2) || bytes.Equal(c, c2) {
				t.Fatal("caller mutated locked metadata")
			}
			r, err := candidate.LockedRuntime(platform)
			if err != nil || r.User != "65532:65532" || r.WorkingDirectory != "/workspace" {
				t.Fatal("runtime config drift")
			}
			r.Command[0], r.Environment[0] = "wrong", "wrong"
			r2, _ := candidate.LockedRuntime(platform)
			if r2.Command[0] == "wrong" || r2.Environment[0] == "wrong" {
				t.Fatal("caller mutated runtime authority")
			}
		})
	}
	for _, platform := range []string{"", "linux/arm64", "linux/arm64/v9", "darwin/arm64", "linux/386"} {
		if _, err := candidate.LockedIdentity(platform); err == nil {
			t.Fatal("unselected platform accepted", platform)
		}
	}
}

func TestCandidateRejectsCallerRebindingEveryIdentityField(t *testing.T) {
	i, err := candidate.LockedIdentity("linux/arm64/v8")
	if err != nil {
		t.Fatal(err)
	}
	good, err := i.Digest()
	if err != nil || good == "" {
		t.Fatal(err)
	}
	for field := range reflect.TypeFor[candidate.Identity]().NumField() {
		t.Run(reflect.TypeFor[candidate.Identity]().Field(field).Name, func(t *testing.T) {
			bad := i
			v := reflect.ValueOf(&bad).Elem().Field(field)
			if v.Kind() == reflect.String {
				v.SetString(v.String() + "-substituted")
			} else {
				v.SetInt(v.Int() + 1)
			}
			if bad.ValidateLocked() == nil {
				t.Fatal("caller changed a reviewed record")
			}
			if d, err := bad.Digest(); err == nil || d != "" {
				t.Fatal("invalid record acquired identity")
			}
		})
	}
}

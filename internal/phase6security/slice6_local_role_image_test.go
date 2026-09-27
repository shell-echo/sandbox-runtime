package phase6security

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSlice6LocalRoleImageInspectBindsSourceTargetAndEntrypoint(t *testing.T) {
	revision := strings.Repeat("a", 40)
	digest := "sha256:" + strings.Repeat("b", 64)
	principal := Principal{Name: "product-runtime", ImageLocation: "local", ImageReference: digest,
		ImageDigest: digest, ImageIdentityKind: ImageIdentityOCIManifest,
		ImagePlatform: "linux/arm64/v8", ImageConfigDigest: "sha256:" + strings.Repeat("c", 64)}
	document := func(id, architecture, target, source, user, entrypoint, mediaType string) []byte {
		value, err := json.Marshal([]any{map[string]any{
			"Id": id, "Os": "linux", "Architecture": architecture,
			"Descriptor": map[string]any{"mediaType": mediaType, "digest": digest},
			"Config": map[string]any{
				"User": user, "Entrypoint": []string{entrypoint},
				"Labels": map[string]string{
					"io.github.shell-echo.sandbox-runtime.phase6-candidate": "local-only-non-release",
					"io.github.shell-echo.sandbox-runtime.source-revision":  source,
					"io.github.shell-echo.sandbox-runtime.role-target":      target,
					"io.github.shell-echo.sandbox-runtime.go-version":       "go1.26.8",
				},
			},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	const manifestType = "application/vnd.oci.image.manifest.v1+json"
	good := document(digest, "arm64", "core", revision, "65532:65532", "/usr/local/bin/phase6-role", manifestType)
	if err := VerifySlice6LocalRoleImageInspect(principal, revision, good); err != nil {
		t.Fatalf("reviewed local role image rejected: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"wrong image ID":         document("sha256:"+strings.Repeat("d", 64), "arm64", "core", revision, "65532:65532", "/usr/local/bin/phase6-role", manifestType),
		"wrong platform":         document(digest, "amd64", "core", revision, "65532:65532", "/usr/local/bin/phase6-role", manifestType),
		"wrong target":           document(digest, "arm64", "gateway", revision, "65532:65532", "/usr/local/bin/phase6-role", manifestType),
		"wrong revision":         document(digest, "arm64", "core", strings.Repeat("d", 40), "65532:65532", "/usr/local/bin/phase6-role", manifestType),
		"root default user":      document(digest, "arm64", "core", revision, "0:0", "/usr/local/bin/phase6-role", manifestType),
		"wrong entrypoint":       document(digest, "arm64", "core", revision, "65532:65532", "/bin/sh", manifestType),
		"wrong descriptor kind":  document(digest, "arm64", "core", revision, "65532:65532", "/usr/local/bin/phase6-role", "application/vnd.oci.image.index.v1+json"),
		"duplicate top-level ID": bytes.Replace(good, []byte(`"Id":"`), []byte(`"Id":"`+digest+`","Id":"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifySlice6LocalRoleImageInspect(principal, revision, candidate); err == nil {
				t.Fatal("substituted local role image admitted")
			}
		})
	}
	for _, name := range []string{"browser-sandbox-runtime", "desktop-sandbox-runtime", "unreviewed-runtime"} {
		candidate := principal
		candidate.Name = name
		if err := VerifySlice6LocalRoleImageInspect(candidate, revision, good); err == nil {
			t.Fatalf("%s acquired local role image authority", name)
		}
	}
}

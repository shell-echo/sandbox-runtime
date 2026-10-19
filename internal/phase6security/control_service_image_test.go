package phase6security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in original OCI archive test. These local fixtures do not carry supply
// attestations and do not inherit any frozen-R release acceptance.
func TestControlBootstrapRealImageBytes(t *testing.T) {
	root := os.Getenv("CONTROL_BOOTSTRAP_IMAGE_TEST")
	if root == "" {
		t.Skip("original local OCI fixtures")
	}
	document, e := os.ReadFile(filepath.Join(root, "profile.json"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := ReviewControlBootstrap(document)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range r.Services {
		t.Run(s.Principal.Name, func(t *testing.T) {
			dir := filepath.Join(root, "images", s.Launch.Target)
			read := func(n string) []byte {
				b, e := os.ReadFile(filepath.Join(dir, n))
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			docs := ImageDescriptorDocuments{Index: read("index.json"), Manifest: read("manifest.json"), Config: read("config.json")}
			proof, e := ReviewControlServiceImage(document, s.Principal.Name, filepath.Join(dir, "image.oci.tar"), docs)
			if e != nil || proof.ConfigDigest != s.Principal.ImageConfigDigest {
				t.Fatal("archive identity", e)
			}
			var p ProfileV2
			_ = json.Unmarshal(document, &p)
			for i := range p.DockerControl.OperatorBootstrap.Launches {
				l := &p.DockerControl.OperatorBootstrap.Launches[i]
				if l.Deployment == s.Principal.Name {
					l.ExecutableDigest = testDigest("wrong actual bytes")
				}
			}
			p.ProfileDigest = p.Digest()
			bad, _ := json.Marshal(p)
			if _, e := ReviewControlServiceImage(bad, s.Principal.Name, filepath.Join(dir, "image.oci.tar"), docs); e == nil {
				t.Fatal("same image wrong executable")
			}
			corrupt := docs
			corrupt.Manifest = append([]byte(nil), docs.Manifest...)
			corrupt.Manifest[0] = '!'
			if _, e := ReviewControlServiceImage(document, s.Principal.Name, filepath.Join(dir, "image.oci.tar"), corrupt); e == nil {
				t.Fatal("tampered original descriptor")
			}
		})
	}
}

func TestControlServiceImageRejectsStartupSideChannels(t *testing.T) {
	base := map[string]any{"Entrypoint": []string{"/usr/local/bin/phase6-role"}, "User": "65532:65532", "WorkingDir": "/", "Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}}
	encode := func(m map[string]any) []byte { b, _ := json.Marshal(map[string]any{"config": m}); return b }
	want := []string{"/usr/local/bin/phase6-role"}
	if !controlServiceConfigMatches(encode(base), want) {
		t.Fatal("closed launch config")
	}
	for key, value := range map[string]any{"Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "ENV=/tmp/hook"}, "Volumes": map[string]any{"/usr/local/bin": map[string]any{}}, "Healthcheck": map[string]any{"Test": []string{"CMD", "sh"}}, "OnBuild": []string{"RUN true"}, "Cmd": []string{"extra"}} {
		t.Run(key, func(t *testing.T) {
			q := map[string]any{}
			for k, v := range base {
				q[k] = v
			}
			q[key] = value
			if controlServiceConfigMatches(encode(q), want) {
				t.Fatal("startup side channel accepted")
			}
		})
	}
}

func TestSourceImageLabelsCannotBeAddedOnlyAtContainerCreate(t *testing.T) {
	s := ControlServiceIdentityV1{Launch: ControlServiceLaunchV1{Target: ControlSourceTarget, SourceRevision: strings.Repeat("a", 40)}}
	raw := func(labels map[string]string) []byte {
		b, _ := json.Marshal(map[string]any{"config": map[string]any{"Labels": labels}})
		return b
	}
	labels := ControlSourceImageLabels(s)
	if !controlSourceLabelsMatch(raw(labels), s) {
		t.Fatal("fixed labels")
	}
	for _, key := range []string{"phase6-candidate", "source-revision", "role-target", "go-version"} {
		t.Run(key, func(t *testing.T) {
			q := ControlSourceImageLabels(s)
			q["io.github.shell-echo.sandbox-runtime."+key] = "wrong"
			if controlSourceLabelsMatch(raw(q), s) {
				t.Fatal("false image metadata")
			}
		})
	}
	labels["extra"] = "unknown"
	if controlSourceLabelsMatch(raw(labels), s) || controlSourceLabelsMatch(raw(nil), s) {
		t.Fatal("unknown or missing image labels")
	}
}

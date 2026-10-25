package phase6rolecandidate

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func candidateTestDirectory(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(path, 0o700) != nil {
		t.Fatal("private physical fixture directory", err)
	}
	return path
}

func candidateTestWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestControlCandidateSpaceBudgetAndEarlyRefusals(t *testing.T) {
	if !candidateSpaceAvailable(uint64(controlWorkspaceBytes)/4096, 4096) ||
		candidateSpaceAvailable(uint64(controlWorkspaceBytes)/4096-1, 4096) ||
		candidateSpaceAvailable(1<<63, 0) || candidateSpaceAvailable(0, -1) {
		t.Fatal("space pressure precheck changed the fixed budget")
	}
	for _, input := range []ControlCandidateInput{{}, {SourceRoot: "."}, {SourceRoot: candidateTestDirectory(t), Profile: "relative"}} {
		if result, err := ReviewControlSourceCandidate(t.Context(), input); err == nil || result != (ControlSourceCandidateReview{}) {
			t.Fatal("invalid candidate returned a result", err)
		}
	}
}

func TestControlCandidateStorageDirectorySelectors(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("candidate storage custody is Darwin/Linux only")
	}
	for _, path := range []string{"relative", "/tmp/./inputs", "/tmp/link/../inputs", "/tmp//inputs"} {
		if _, err := candidateDirectorySelector(path); err == nil {
			t.Fatalf("noncanonical selector admitted: %q", path)
		}
	}
	root := candidateTestDirectory(t)
	if path, err := candidateDirectorySelector(root + string(filepath.Separator)); err != nil || path != root {
		t.Fatal("directory tail separator refused", err)
	}
	source := candidateTestDirectory(t)
	work := candidateTestDirectory(t)
	t.Setenv("TMPDIR", root+string(filepath.Separator))
	if err := candidateStorageSpace(t.Context(), source, work); err != nil {
		t.Fatal("standard TMPDIR selector refused", err)
	}
	t.Setenv("GOCACHE", source+string(filepath.Separator))
	if err := candidateStorageSpace(t.Context(), source, work); err == nil {
		t.Fatal("source cache alias admitted")
	}
	t.Setenv("GOCACHE", filepath.Join(work, "snapshot"))
	if err := candidateStorageSpace(t.Context(), source, work); err == nil {
		t.Fatal("snapshot cache alias admitted")
	}
}

type controlCandidateFixture struct {
	input        ControlCandidateInput
	profile      phase6security.ProfileV2
	binaries     map[string][]byte
	pin          string
	public       []byte
	platform     string
	configChange func(map[string]any)
}

func newControlCandidateFixture(t *testing.T) controlCandidateFixture {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("candidate input custody is Darwin/Linux only")
	}
	template := os.Getenv("SANDBOX_RUNTIME_CONTROL_SOURCE_PROFILE")
	if template == "" {
		t.Skip("explicit synthetic complete Profile required")
	}
	directory := os.Getenv("SANDBOX_RUNTIME_CONTROL_SOURCE_CASE_OUTPUT")
	if directory == "" {
		directory = candidateTestDirectory(t)
	} else {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(directory, "source")
	data := filepath.Join(directory, "data")
	bin := filepath.Join(directory, "binaries")
	for _, path := range []string{root, data, bin} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"go.mod":                                "module github.com/shell-echo/sandbox-runtime\n\ngo 1.26.8\n",
		"go.sum":                                "\n",
		"cmd/provider-docker-control/main.go":   "package main\nimport \"github.com/shell-echo/sandbox-runtime/internal/controlbootstrap\"\nfunc main(){ println(controlbootstrap.Pin()) }\n",
		"internal/controlbootstrap/pin.go":      "package controlbootstrap\nvar publicKeyPin string\nfunc Pin() string { return publicKeyPin }\n",
		"cmd/phase6-fd-loader/main.go":          "package main\nfunc main(){println(\"synthetic loader\")}\n",
		"tools/control-process-observe/main.go": "package main\nfunc main(){println(\"synthetic probe\")}\n",
	}
	for _, name := range []string{"Dockerfile", "build.sh"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "local-role", name))
		if err != nil {
			t.Fatal(err)
		}
		files["profiles/phase6/local-role/"+name] = string(raw)
	}
	for name, raw := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		candidateTestWrite(t, path, []byte(raw))
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=CandidateTest", "-c", "user.email=candidate@example.test", "commit", "-qm", "synthetic source"}} {
		command := exec.CommandContext(t.Context(), "git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"}, args...)...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("synthetic Git: %s, %v", output, err)
		}
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := controlCandidateFixture{input: ControlCandidateInput{SourceRoot: root, Profile: filepath.Join(data, "profile.json"), PublicKey: filepath.Join(data, "operator.pub"), Archive: filepath.Join(data, "image.oci.tar")}, binaries: map[string][]byte{}, pin: hashBytes(pub), public: append([]byte(nil), pub...)}
	candidateTestWrite(t, f.input.PublicKey, pub)
	raw, err := os.ReadFile(template)
	if err != nil || json.Unmarshal(raw, &f.profile) != nil {
		t.Fatal("synthetic declaration template", err)
	}
	flags := "-buildid= -X github.com/shell-echo/sandbox-runtime/internal/controlbootstrap.publicKeyPin=" + f.pin
	source, err := collectSourceInputs(t.Context(), root, "provider-docker-control", "linux/arm64/v8", phase6security.ControlTrustTarget,
		roleBuildRecipe{"./cmd/provider-docker-control", "control-delivery"}, flags)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, pkg, flags string }{
		{"role", "./cmd/provider-docker-control", flags}, {"loader", "./cmd/phase6-fd-loader", "-buildid="}, {"probe", "./tools/control-process-observe", "-buildid="},
	} {
		f.binaries[item.name], err = rebuildExecutable(t.Context(), root, filepath.Join(bin, item.name), "linux/arm64/v8", item.pkg, item.flags)
		if err != nil {
			t.Fatal(err)
		}
	}
	if embeddedControlPin(t, f.binaries["role"]) != f.pin {
		t.Fatal("linker did not provision the actual string variable")
	}
	for i := range f.profile.DockerControl.OperatorBootstrap.Launches {
		l := &f.profile.DockerControl.OperatorBootstrap.Launches[i]
		if l.Deployment == "provider-docker-control" {
			l.SourceRevision, l.SourceTreeDigest = source.SourceRevision, source.SourceTreeDigest
			l.ExecutableDigest, l.LoaderDigest, l.ProbeDigest = hashBytes(f.binaries["role"]), hashBytes(f.binaries["loader"]), hashBytes(f.binaries["probe"])
		}
	}
	f.profile.DockerControl.OperatorBootstrap.KeyDigest = f.pin
	f.archive(t, true)
	request, _ := json.Marshal(f.input)
	candidateTestWrite(t, filepath.Join(data, "input.json"), request)
	return f
}

// Read the linked variable's string header and referenced bytes, not a matching
// string in build metadata. These Linux fixtures are never executed on the host.
func embeddedControlPin(t *testing.T, data []byte) string {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil || f.Class != elf.ELFCLASS64 || f.ByteOrder != binary.LittleEndian {
		t.Fatal("ELF64 fixture", err)
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	read := func(address, size uint64) []byte {
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && address >= p.Vaddr && size <= p.Filesz && address-p.Vaddr <= p.Filesz-size {
				offset := p.Off + address - p.Vaddr
				if offset <= uint64(len(data)) && size <= uint64(len(data))-offset {
					return data[offset : offset+size]
				}
			}
		}
		t.Fatal("linked string is outside file-backed segments")
		return nil
	}
	for _, s := range symbols {
		if s.Name == "github.com/shell-echo/sandbox-runtime/internal/controlbootstrap.publicKeyPin" {
			header := read(s.Value, 16)
			return string(read(binary.LittleEndian.Uint64(header), binary.LittleEndian.Uint64(header[8:])))
		}
	}
	t.Fatal("linked pin symbol missing")
	return ""
}

func (f *controlCandidateFixture) archive(t *testing.T, validProfile bool) {
	t.Helper()
	var layer bytes.Buffer
	w := tar.NewWriter(&layer)
	for _, item := range []struct{ name, target string }{{"role", "phase6-role"}, {"loader", "phase6-fd-loader"}, {"probe", "control-process-observe"}} {
		data := f.binaries[item.name]
		if w.WriteHeader(&tar.Header{Name: "usr/local/bin/" + item.target, Typeflag: tar.TypeReg, Mode: 0o555, Size: int64(len(data))}) != nil {
			t.Fatal("layer header")
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if w.Close() != nil {
		t.Fatal("layer close")
	}
	marshal := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	labels := phase6security.ControlSourceImageLabels(phase6security.ControlServiceIdentityV1{Launch: phase6security.ControlServiceLaunchV1{Target: phase6security.ControlTrustTarget}})
	for _, l := range f.profile.DockerControl.OperatorBootstrap.Launches {
		if l.Deployment == "provider-docker-control" {
			labels = phase6security.ControlSourceImageLabels(phase6security.ControlServiceIdentityV1{Launch: l})
		}
	}
	platform, architecture, variant := f.platform, "arm64", "v8"
	if platform == "" {
		platform = "linux/arm64/v8"
	}
	if platform == "linux/amd64" {
		architecture, variant = "amd64", ""
	}
	configuration := map[string]any{"User": "65532:65532", "WorkingDir": "/", "Entrypoint": []string{"/bin/sh", "-ec", "exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader"}, "Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, "Labels": labels}
	if f.configChange != nil {
		f.configChange(configuration)
	}
	config := marshal(map[string]any{"architecture": architecture, "os": "linux", "variant": variant, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{hashBytes(layer.Bytes())}}, "config": configuration})
	descriptor := func(data []byte, media string) map[string]any {
		return map[string]any{"mediaType": media, "digest": hashBytes(data), "size": len(data)}
	}
	manifest := marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": descriptor(config, "application/vnd.oci.image.config.v1+json"), "layers": []any{descriptor(layer.Bytes(), "application/vnd.oci.image.layer.v1.tar")}})
	selected := descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
	selected["platform"] = map[string]any{"os": "linux", "architecture": architecture, "variant": variant}
	index := marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{selected}})
	var archive bytes.Buffer
	w = tar.NewWriter(&archive)
	for _, data := range [][]byte{index, manifest, config, layer.Bytes()} {
		if w.WriteHeader(&tar.Header{Name: "blobs/sha256/" + strings.TrimPrefix(hashBytes(data), "sha256:"), Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data))}) != nil {
			t.Fatal("archive header")
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if w.Close() != nil {
		t.Fatal("archive close")
	}
	candidateTestWrite(t, f.input.Archive, archive.Bytes())
	for i := range f.profile.Principals {
		p := &f.profile.Principals[i]
		if p.Name == "provider-docker-control" {
			p.ImageLocation, p.ImageIdentityKind = "local", phase6security.ImageIdentityOCIIndex
			p.ImageDigest, p.ImageReference = hashBytes(index), hashBytes(index)
			p.ImageSelectedManifestDigest, p.ImageConfigDigest, p.ImagePlatform = hashBytes(manifest), hashBytes(config), platform
			a := f.profile.DockerControl.SourceAccess
			var err error
			a.Intent, err = phase6security.NewControlSourceIntentV1(a.Intent.Namespace, *p, a.Intent.SocketSource)
			if err != nil {
				t.Fatal(err)
			}
			a.IntentDigest, err = a.Intent.Digest()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if validProfile {
		f.writeProfile(t)
	} else {
		f.profile.ProfileDigest = f.profile.Digest()
		raw, err := json.Marshal(f.profile)
		if err != nil {
			t.Fatal(err)
		}
		candidateTestWrite(t, f.input.Profile, raw)
	}
}

func (f *controlCandidateFixture) writeProfile(t *testing.T) {
	t.Helper()
	f.profile.ProfileDigest = f.profile.Digest()
	raw, err := json.Marshal(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase6security.ReviewControlBootstrap(raw); err != nil {
		t.Fatal("complete synthetic Profile", err)
	}
	candidateTestWrite(t, f.input.Profile, raw)
}

func TestControlSourceCandidateSyntheticCorrespondenceAndPin(t *testing.T) {
	f := newControlCandidateFixture(t)
	result, err := ReviewControlSourceCandidate(t.Context(), f.input)
	if err != nil || result.Admission != "held-not-a-permit" || result.OperatorKeyOrigin != "not-verified" || result.Classification != "offline-byte-correspondence-only" || result.PublicKeyDigest != f.pin || result.ProbeDigest != hashBytes(f.binaries["probe"]) {
		t.Fatal("synthetic source byte correspondence", result, err)
	}
	if f.profile.Validate() == nil {
		t.Fatal("public admission hold removed")
	}
	if _, err := CollectSourceInputs(t.Context(), f.input.SourceRoot, "provider-docker-control", "linux/arm64/v8"); err == nil {
		t.Fatal("Control entered ordinary image supply")
	}
	profileBytes, _ := os.ReadFile(f.input.Profile)
	archiveBytes, _ := os.ReadFile(f.input.Archive)
	for _, name := range []string{"missing key", "private key length", "public key mode", "wrong key", "dirty source", "lock drift", "source revision", "source tree", "old target", "archive bytes"} {
		t.Run(name, func(t *testing.T) {
			input := f.input
			var p phase6security.ProfileV2
			if err := json.Unmarshal(profileBytes, &p); err != nil {
				t.Fatal(err)
			}
			dirty := filepath.Join(f.input.SourceRoot, "untracked")
			lock := filepath.Join(f.input.SourceRoot, "go.sum")
			defer func() {
				candidateTestWrite(t, f.input.PublicKey, f.public)
				if err := os.Chmod(f.input.PublicKey, 0o600); err != nil {
					t.Fatal(err)
				}
				candidateTestWrite(t, f.input.Profile, profileBytes)
				candidateTestWrite(t, f.input.Archive, archiveBytes)
				candidateTestWrite(t, lock, []byte("\n"))
				if err := os.Remove(dirty); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}()
			switch name {
			case "missing key":
				input.PublicKey += ".missing"
			case "private key length":
				candidateTestWrite(t, input.PublicKey, make([]byte, 64))
			case "public key mode":
				if err := os.Chmod(input.PublicKey, 0o644); err != nil {
					t.Fatal(err)
				}
			case "wrong key":
				candidateTestWrite(t, input.PublicKey, bytes.Repeat([]byte{9}, 32))
			case "dirty source":
				candidateTestWrite(t, dirty, []byte("dirty\n"))
			case "lock drift":
				candidateTestWrite(t, lock, []byte("changed\n"))
			case "source revision", "source tree":
				for i := range p.DockerControl.OperatorBootstrap.Launches {
					l := &p.DockerControl.OperatorBootstrap.Launches[i]
					if l.Deployment == "provider-docker-control" {
						if name == "source revision" {
							l.SourceRevision = strings.Repeat("b", 40)
						} else {
							l.SourceTreeDigest = hashBytes([]byte("other source"))
						}
					}
				}
			case "old target":
				p.DockerControl.OperatorBootstrap.Target = phase6security.ControlSourceTarget
			case "archive bytes":
				bad := append([]byte(nil), archiveBytes...)
				bad[1024] ^= 1
				candidateTestWrite(t, input.Archive, bad)
			}
			if name == "source revision" || name == "source tree" || name == "old target" {
				p.ProfileDigest = p.Digest()
				raw, _ := json.Marshal(p)
				candidateTestWrite(t, input.Profile, raw)
			}
			if result, err := ReviewControlSourceCandidate(t.Context(), input); err == nil || result != (ControlSourceCandidateReview{}) {
				t.Fatal("invalid source candidate returned a result", err)
			}
		})
	}
	for _, name := range []string{"role", "loader", "probe"} {
		t.Run("wrong-built-"+name, func(t *testing.T) {
			original := f.binaries[name]
			defer func() {
				f.binaries[name] = original
				var restored phase6security.ProfileV2
				if err := json.Unmarshal(profileBytes, &restored); err != nil {
					t.Fatal(err)
				}
				f.profile = restored
				f.archive(t, true)
			}()
			f.binaries[name] = []byte("not the selected source executable")
			for i := range f.profile.DockerControl.OperatorBootstrap.Launches {
				l := &f.profile.DockerControl.OperatorBootstrap.Launches[i]
				if l.Deployment == "provider-docker-control" {
					switch name {
					case "role":
						l.ExecutableDigest = hashBytes(f.binaries[name])
					case "loader":
						l.LoaderDigest = hashBytes(f.binaries[name])
					case "probe":
						l.ProbeDigest = hashBytes(f.binaries[name])
					}
				}
			}
			f.archive(t, true)
			if result, err := ReviewControlSourceCandidate(t.Context(), f.input); err == nil || result != (ControlSourceCandidateReview{}) {
				t.Fatal("self-consistent wrong executable was accepted", err)
			}
		})
	}
	for _, name := range []string{"platform", "config"} {
		t.Run("self-consistent-wrong-"+name, func(t *testing.T) {
			defer func() {
				f.platform, f.configChange = "", nil
				var restored phase6security.ProfileV2
				if err := json.Unmarshal(profileBytes, &restored); err != nil {
					t.Fatal(err)
				}
				f.profile = restored
				f.archive(t, true)
			}()
			if name == "platform" {
				f.platform = "linux/amd64"
			} else {
				f.configChange = func(c map[string]any) {
					c["Env"] = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "ENV=/tmp/hook"}
				}
			}
			// Platform metadata is internally matched but contradicts the fixed
			// complete Profile. Let the real API reject that input, rather than
			// stopping inside the fixture producer's positive-only validator.
			f.archive(t, name != "platform")
			result, err := ReviewControlSourceCandidate(t.Context(), f.input)
			if err == nil || result != (ControlSourceCandidateReview{}) {
				t.Fatal("self-consistent wrong platform/config accepted", err)
			}
			if name == "config" && !strings.Contains(err.Error(), "service-image") {
				t.Fatal("configuration refusal did not reach the selected image check", err)
			}
		})
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	changedPin := hashBytes(pub)
	changed, err := rebuildExecutable(t.Context(), f.input.SourceRoot, filepath.Join(candidateTestDirectory(t), "changed-role"), "linux/arm64/v8", "./cmd/provider-docker-control", "-buildid= -X github.com/shell-echo/sandbox-runtime/internal/controlbootstrap.publicKeyPin="+changedPin)
	if err != nil || bytes.Equal(changed, f.binaries["role"]) || embeddedControlPin(t, changed) != changedPin {
		t.Fatal("changed pin was not actually linked", err)
	}
	candidateTestWrite(t, f.input.PublicKey, pub)
	f.profile.DockerControl.OperatorBootstrap.KeyDigest = changedPin
	f.writeProfile(t)
	if result, err := ReviewControlSourceCandidate(t.Context(), f.input); err == nil || result != (ControlSourceCandidateReview{}) {
		t.Fatal("changed pin+declaration accepted old OCI", err)
	}
	// Preserve the successful original fixture for a separately supervised CLI
	// invocation, without reclassifying this synthetic source as project source.
	if os.Getenv("SANDBOX_RUNTIME_CONTROL_SOURCE_CASE_OUTPUT") != "" {
		candidateTestWrite(t, f.input.PublicKey, f.public)
		f.profile.DockerControl.OperatorBootstrap.KeyDigest = f.pin
		f.writeProfile(t)
	}
}

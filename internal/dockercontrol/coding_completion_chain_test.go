package dockercontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	ocidigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func testCodingRawDocuments(t *testing.T) phase6security.ImageDescriptorDocuments {
	t.Helper()
	root := filepath.Join("testdata", "coding-oci-arm64-v8")
	read := func(name string) []byte {
		value, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(value) < 1 || len(value) > 4<<20 {
			t.Fatalf("missing bounded raw OCI %s: %v", name, err)
		}
		return value
	}
	documents := phase6security.ImageDescriptorDocuments{Index: read("index.json"),
		Manifest: read("manifest.json"), Config: read("config.json")}
	publication := codingimage.LockedPublication()
	proof, err := phase6security.VerifyImageDescriptorDocuments("registry",
		phase6security.ImageIdentityOCIIndex, publication.Image(), publication.Digest,
		"linux/arm64/v8", codingimage.PublishedARM64V8Digest,
		codingimage.PublishedARM64ConfigDigest, documents)
	if err != nil || proof.ConfigDigest != codingimage.PublishedARM64ConfigDigest {
		t.Fatalf("raw OCI fixture has drifted: %v", err)
	}
	return documents
}

type codingCompletionFixture struct {
	observer *codingUnixObserver
	receipt  CodingReceipt
	revision uint64
	set      CodingResourceSet
	ticket   codingidentity.Reservation
	sandbox  lifecycle.Sandbox
	respond  func(*http.Request) (*http.Response, error)
	calls    *[]string
}

func testCodingCompletionFixture(t *testing.T) codingCompletionFixture {
	t.Helper()
	documents := testCodingRawDocuments(t)
	ticket, operation, sandbox, plan, now := testCodingCreate(t)
	policy := []byte("fixed-test-policy")
	policySum := sha256.Sum256(policy)
	template, err := phase6security.NewCodingRuntimeTemplateV2("linux/arm64/v8",
		codingimage.PublishedARM64ConfigDigest, codingimage.PublishedDescriptorSize,
		plan.OwnerPrincipalDigest, "sha256:"+hex.EncodeToString(policySum[:]), plan.Slots, plan.Limits)
	if err != nil {
		t.Fatal(err)
	}
	plan.TemplateDigest, err = template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.ImageDigest, plan.ImageConfigDigest = template.Image.Descriptor.Digest, template.Image.ConfigDigest
	ticket.PlanDigest, err = plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewCodingCreateAuthority(t.Context(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	binding := testReceiptBinding(authority, plan)
	state, err := NewCodingReceiptState(binding)
	if err != nil {
		t.Fatal(err)
	}
	state, receipt, _, err := state.beginUnknown(binding, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		t.Fatal(err)
	}
	labels, err := set.ContainerLabels(CodingRuntimeRole, template, documents)
	if err != nil {
		t.Fatal(err)
	}
	runtimeName, _ := set.ContainerName(CodingRuntimeRole)
	prepName, _ := set.ContainerName(CodingPreparationRole)
	runtimeID := strings.Repeat("a", 64)
	slot := template.Slots[0]
	mounts := set.Mounts()
	configured := make([]mount.Mount, 0, len(mounts))
	realized := make([]container.MountPoint, 0, len(mounts))
	for _, item := range mounts {
		configured = append(configured, mount.Mount{Type: mount.TypeVolume,
			Source: item.Name, Target: item.Target, ReadOnly: item.ReadOnly,
			VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
		realized = append(realized, container.MountPoint{Type: mount.TypeVolume,
			Name: item.Name, Destination: item.Target, RW: !item.ReadOnly})
	}
	platform, _ := codingOCIPlatform(template.Image.Platform)
	selectedDescriptor := &ocispec.Descriptor{Digest: ocidigest.Digest(template.Image.SelectedManifestDigest),
		MediaType: "application/vnd.oci.image.manifest.v1+json", Size: template.Image.SelectedManifestSize,
		Platform: &platform}
	pids := template.Limits.PIDs
	runtime := container.InspectResponse{ID: runtimeID, Name: "/" + runtimeName,
		Image: template.Image.Descriptor.Digest, ImageManifestDescriptor: selectedDescriptor,
		State: &container.State{Status: "running", Running: true, Pid: 123,
			StartedAt: now.Format(time.RFC3339Nano)},
		Config: &container.Config{Image: template.Image.Reference,
			User:       fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID),
			WorkingDir: template.WorkingDirectory, Cmd: slices.Clone(template.Command),
			Env: slices.Clone(template.Environment), Labels: labels},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode("none"),
			ReadonlyRootfs: true, RestartPolicy: container.RestartPolicy{Name: "no"},
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + string(policy)},
			Mounts: configured, Tmpfs: map[string]string{"/tmp": fmt.Sprintf(
				"rw,noexec,nosuid,nodev,size=%d,mode=0700,uid=%d,gid=%d",
				template.TmpfsBytes, slot.WorkloadUID, slot.WorkloadGID)},
			Resources: container.Resources{Memory: template.Limits.MemoryBytes,
				MemorySwap: template.Limits.MemoryBytes,
				NanoCPUs:   template.Limits.CPUMillis * 1_000_000, PidsLimit: &pids}},
		Mounts: realized, NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{"none": {}}},
	}
	if validateCodingRuntimeInspect(runtime, runtimeID, runtimeName, labels,
		template, slot, mounts, string(policy)) != nil {
		t.Fatal("positive runtime fixture is not closed")
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(documents.Config, &config) != nil || len(config.RootFS.DiffIDs) == 0 {
		t.Fatal("raw OCI config has no rootfs diff IDs")
	}
	indexImage := image.InspectResponse{ID: template.Image.Descriptor.Digest,
		Descriptor: &ocispec.Descriptor{Digest: ocidigest.Digest(template.Image.Descriptor.Digest),
			MediaType: "application/vnd.oci.image.index.v1+json", Size: template.Image.Descriptor.Size},
		Os: "linux", Architecture: "arm64", Variant: "v8",
		RootFS: image.RootFS{Type: "layers", Layers: config.RootFS.DiffIDs}}
	manifest, err := codingimage.LockedManifest()
	if err != nil {
		t.Fatal(err)
	}
	selectedImage := image.InspectResponse{ID: template.Image.ConfigDigest, Descriptor: selectedDescriptor,
		Os: "linux", Architecture: "arm64", Variant: "v8",
		Config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{
			Env: slices.Clone(template.Environment), Cmd: slices.Clone(manifest.Runtime.Command),
			WorkingDir: template.WorkingDirectory, User: "65532:65532"}}}
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	volumeDocuments := map[string]string{}
	var listedVolumes []volume.Volume
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := set.VolumeName(role)
		volumeLabels, _ := set.Labels(role)
		item := volume.Volume{Name: name, Driver: "local", Scope: "local", Labels: volumeLabels}
		volumeDocuments["/v1.55/volumes/"+name] = encode(item)
		listedVolumes = append(listedVolumes, item)
	}
	listContainers := encode([]container.Summary{{ID: runtimeID,
		Names: []string{"/" + runtimeName}, Labels: labels}})
	listVolumes := encode(struct {
		Volumes  []volume.Volume
		Warnings []string
	}{listedVolumes, nil})
	runtimeDocument := encode(runtime)
	indexDocument, selectedDocument := encode(indexImage), encode(selectedImage)
	infoDocument := encode(codingInfoFixture())
	var calls []string
	respond := func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.URL.String())
		path := request.URL.Path
		if path == "/v1.55/containers/"+runtimeID+"/archive" {
			target := request.URL.Query().Get("path")
			return codingArchiveResponse(t, target, codingArchiveFixture(t, target, nil)), nil
		}
		if document, ok := volumeDocuments[path]; ok {
			return codingSDKResponse(http.StatusOK, document, "application/json"), nil
		}
		switch path {
		case "/v1.55/info":
			return codingSDKResponse(http.StatusOK, infoDocument, "application/json"), nil
		case "/v1.55/containers/" + prepName + "/json":
			return codingSDKResponse(http.StatusNotFound, `{"message":"No such container"}`, "application/json"), nil
		case "/v1.55/containers/" + runtimeName + "/json":
			return codingSDKResponse(http.StatusOK, runtimeDocument, "application/json"), nil
		case "/v1.55/containers/json":
			return codingSDKResponse(http.StatusOK, listContainers, "application/json"), nil
		case "/v1.55/volumes":
			return codingSDKResponse(http.StatusOK, listVolumes, "application/json"), nil
		case "/v1.55/images/" + template.Image.Reference + "/json":
			if request.URL.RawQuery == "" {
				return codingSDKResponse(http.StatusOK, indexDocument, "application/json"), nil
			}
			return codingSDKResponse(http.StatusOK, selectedDocument, "application/json"), nil
		default:
			t.Fatalf("unexpected fake daemon GET path: %s", path)
			return nil, ErrInvalidCodingObservationTransport
		}
	}
	bounded := &codingObservationTransport{base: codingRoundTripFunc(respond), set: set,
		endpointHost: "/run/docker.sock", requestHost: client.DummyHost,
		imageRef: template.Image.Reference, platform: template.Image.Platform,
		archiveUID: int(slot.WorkloadUID), archiveGID: int(slot.WorkloadGID),
		archiveMode: int64(template.VolumePrepMode)}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration}),
		client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = api.Close() })
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	observer := &codingUnixObserver{gate: gate, api: api, bounded: bounded,
		binding: binding, authority: authority, template: template,
		documents: documents, policy: policy}
	return codingCompletionFixture{observer: observer, receipt: receipt, revision: state.Revision,
		set: set, ticket: ticket, sandbox: sandbox, respond: respond, calls: &calls}
}

func TestCodingCompleteObservationPositiveLockedOCIThroughBoundedSDK(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	proof, err := fixture.observer.observeCompleted(context.Background(), fixture.receipt, fixture.revision)
	if err != nil || proof.CompletionDigest == "" || proof.RuntimeID != strings.Repeat("a", 64) {
		t.Fatalf("full positive read-only completion chain: %#v, %v", proof, err)
	}
	if len(*fixture.calls) != 23 {
		t.Fatalf("complete exact GET count = %d, want 23", len(*fixture.calls))
	}
	if fixture.observer.bounded.archiveID != "" {
		t.Fatal("runtime archive authority remained open after observation")
	}
	for _, item := range proof.ArchiveDigests {
		if !controlDigest.MatchString(item) {
			t.Fatal("empty-root proof missing")
		}
	}
	if err := proof.recheck(fixture.observer.binding, fixture.observer.authority,
		fixture.observer.template, fixture.observer.documents, fixture.observer.policy); err != nil {
		t.Fatalf("source-produced private projection did not independently recheck: %v", err)
	}
}

func TestCodingCompletionProjectionTamperingFailsIndependentRecheck(t *testing.T) {
	for _, mutation := range []struct {
		name string
		edit func(*codingCompletionObservation)
	}{
		{"zero revision", func(p *codingCompletionObservation) { p.ReceiptRevision = 0 }},
		{"inventory scope", func(p *codingCompletionObservation) { p.FinalInventory.Volumes[0].Scope = "global" }},
		{"runtime privilege", func(p *codingCompletionObservation) { p.FinalRuntime.GroupAddCount = 1 }},
		{"runtime network", func(p *codingCompletionObservation) { p.FinalRuntime.NetworkMode = "host" }},
		{"duplicate tmpfs", func(p *codingCompletionObservation) {
			entry := codingSafeMount{Type: "tmpfs", Target: "/tmp"}
			p.InitialRuntime.RealizedMounts = append(p.InitialRuntime.RealizedMounts, entry, entry)
			p.FinalRuntime.RealizedMounts = append(p.FinalRuntime.RealizedMounts, entry, entry)
		}},
		{"image manifest", func(p *codingCompletionObservation) {
			p.Image.SelectedManifestDescriptor.Digest = testControlDigest("0")
		}},
		{"root owner", func(p *codingCompletionObservation) { p.ArchiveRoots[0].ArchiveUID = 57000 }},
		{"completion digest", func(p *codingCompletionObservation) { p.CompletionDigest = testControlDigest("0") }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			proof, err := fixture.observer.observeCompleted(t.Context(), fixture.receipt, fixture.revision)
			if err != nil {
				t.Fatal(err)
			}
			mutation.edit(&proof)
			if mutation.name != "completion digest" {
				withoutChecksum := proof
				withoutChecksum.CompletionDigest = ""
				document, err := json.Marshal(withoutChecksum)
				if err != nil {
					t.Fatal(err)
				}
				proof.CompletionDigest = digest(append(
					[]byte("sandbox-runtime/docker-control-coding-completion/v1\x00"), document...))
			}
			if proof.recheck(fixture.observer.binding, fixture.observer.authority,
				fixture.observer.template, fixture.observer.documents, fixture.observer.policy) == nil {
				t.Fatal("tampered private proof rechecked as valid")
			}
		})
	}
}

func TestCodingCompleteObservationRejectsReceiptAndRevisionBeforeDocker(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		mutate func(*CodingReceipt, *uint64)
	}{
		{"wrong effect", func(receipt *CodingReceipt, _ *uint64) {
			receipt.Authority.EffectID = testControlDigest("0")
		}},
		{"fabricated completed", func(receipt *CodingReceipt, _ *uint64) {
			receipt.Status, receipt.CompletionDigest = ReceiptCompleted, testControlDigest("0")
		}},
		{"zero revision", func(_ *CodingReceipt, revision *uint64) { *revision = 0 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			mutation.mutate(&fixture.receipt, &fixture.revision)
			if _, err := fixture.observer.observeCompleted(t.Context(), fixture.receipt, fixture.revision); err == nil ||
				len(*fixture.calls) != 0 {
				t.Fatalf("invalid receipt reached Docker: %v, GETs=%d", err, len(*fixture.calls))
			}
		})
	}
}

func TestCodingCompleteObservationRejectsPhysicalDriftAtExactBranch(t *testing.T) {
	for _, mutation := range []struct {
		name string
		path func(codingCompletionFixture) string
		nth  int
		edit func(*testing.T, *http.Response) *http.Response
	}{
		{"runtime id", func(f codingCompletionFixture) string {
			name, _ := f.set.ContainerName(CodingRuntimeRole)
			return "/v1.55/containers/" + name + "/json"
		}, 2, func(t *testing.T, response *http.Response) *http.Response {
			return codingRewriteJSONResponse(t, response, func(body string) string {
				return strings.Replace(body, `"Id":"`+strings.Repeat("a", 64)+`"`, `"Id":"`+strings.Repeat("b", 64)+`"`, 1)
			})
		}},
		{"runtime supplementary root group", func(f codingCompletionFixture) string {
			name, _ := f.set.ContainerName(CodingRuntimeRole)
			return "/v1.55/containers/" + name + "/json"
		}, 2, func(t *testing.T, response *http.Response) *http.Response {
			return codingRewriteJSONResponse(t, response, func(body string) string {
				return strings.Replace(body, `"HostConfig":{`, `"HostConfig":{"GroupAdd":["0"],`, 1)
			})
		}},
		{"volume label", func(f codingCompletionFixture) string {
			name, _ := f.set.VolumeName(CodingInputsRole)
			return "/v1.55/volumes/" + name
		}, 1, func(t *testing.T, response *http.Response) *http.Response {
			return codingRewriteJSONResponse(t, response, func(body string) string {
				prefix := `"` + codingEffectLabel + `":"`
				begin := strings.Index(body, prefix)
				if begin < 0 {
					return body
				}
				begin += len(prefix)
				end := strings.IndexByte(body[begin:], '"')
				if end < 0 {
					return body
				}
				return body[:begin] + "foreign" + body[begin+end:]
			})
		}},
		{"selected image digest", func(f codingCompletionFixture) string {
			return "/v1.55/images/" + f.observer.template.Image.Reference + "/json"
		}, 2, func(t *testing.T, response *http.Response) *http.Response {
			return codingRewriteJSONResponse(t, response, func(body string) string {
				return strings.Replace(body, codingimage.PublishedARM64V8Digest, testControlDigest("0"), 1)
			})
		}},
		{"inputs path stat", func(_ codingCompletionFixture) string {
			return "/archive"
		}, 1, func(t *testing.T, response *http.Response) *http.Response {
			return codingArchiveResponse(t, "/workspace", codingArchiveFixture(t, "/workspace", nil))
		}},
		{"final runtime id", func(f codingCompletionFixture) string {
			name, _ := f.set.ContainerName(CodingRuntimeRole)
			return "/v1.55/containers/" + name + "/json"
		}, 3, func(t *testing.T, response *http.Response) *http.Response {
			return codingRewriteJSONResponse(t, response, func(body string) string {
				return strings.Replace(body, `"Id":"`+strings.Repeat("a", 64)+`"`, `"Id":"`+strings.Repeat("b", 64)+`"`, 1)
			})
		}},
		{"final list", func(_ codingCompletionFixture) string { return "/v1.55/containers/json" }, 2,
			func(_ *testing.T, _ *http.Response) *http.Response {
				return codingSDKResponse(http.StatusOK, `[]`, "application/json")
			}},
		{"daemon environment", func(_ codingCompletionFixture) string { return "/v1.55/info" }, 2,
			func(t *testing.T, response *http.Response) *http.Response {
				return codingRewriteJSONResponse(t, response, func(body string) string {
					return strings.Replace(body, `"ServerVersion":"29.7.2"`, `"ServerVersion":"29.7.3"`, 1)
				})
			}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fixture := testCodingCompletionFixture(t)
			original := fixture.respond
			wantPath := mutation.path(fixture)
			hits, changed := 0, false
			fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := original(request)
				if err != nil {
					return response, err
				}
				matching := request.URL.Path == wantPath || wantPath == "/archive" &&
					strings.HasSuffix(request.URL.Path, "/archive")
				if matching {
					hits++
					if hits == mutation.nth {
						changed = true
						return mutation.edit(t, response), nil
					}
				}
				return response, nil
			})
			if _, err := fixture.observer.observeCompleted(t.Context(), fixture.receipt, fixture.revision); err == nil || !changed {
				t.Fatalf("drift did not fail at intended physical branch: %v, changed=%t, GETs=%d", err, changed, len(*fixture.calls))
			}
			if fixture.observer.bounded.archiveID != "" {
				t.Fatal("archive authority remained enabled after failed observation")
			}
		})
	}
}

func codingRewriteJSONResponse(t *testing.T, response *http.Response, edit func(string) string) *http.Response {
	t.Helper()
	old, err := io.ReadAll(response.Body)
	if err != nil || response.Body.Close() != nil {
		t.Fatal("cannot rewrite in-memory fake daemon fixture")
	}
	changed := edit(string(old))
	if changed == string(old) || !json.Valid([]byte(changed)) {
		t.Fatal("mutation failed to change one valid JSON response")
	}
	response.Body = io.NopCloser(strings.NewReader(changed))
	response.ContentLength = int64(len(changed))
	return response
}

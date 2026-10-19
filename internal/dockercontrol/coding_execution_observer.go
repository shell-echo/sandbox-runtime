package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingcandidate "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

// A held source component, not a Profile-v2 constructor or a Docker mutation
// port. The endpoint must be supplied by the future admitted source binding.
type executionUnixObserver struct {
	gate      chan struct{}
	api       *client.Client
	transport *http.Transport
	bounded   *executionObservationTransport
	binding   executionBinding
	create    executionCreate
	documents phase6security.ImageDescriptorDocuments
	policy    []byte
}

func newExecutionUnixObserver(endpoint codingBoundUnixEndpoint, b executionBinding, a executionCreate, d phase6security.ImageDescriptorDocuments, policy []byte) (*executionUnixObserver, error) {
	if b.validate() != nil || a.validate(b, a.IssuedAt) != nil || endpoint.scopeDigest != b.EndpointScopeDigest ||
		verifyCodingUnixSocket(endpoint.path) != nil || len(policy) == 0 || len(policy) > 64<<10 || digest(policy) != b.Template.SeccompPolicyDigest {
		return nil, ErrInvalidCodingUnixObserver
	}
	if _, err := executionContainerLabels(b, a, "resident", d); err != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	b = b.clone()
	d = cloneExecutionDocuments(d)
	policy = slices.Clone(policy)
	identity, err := os.Lstat(endpoint.path)
	if err != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	sameSocket := func() bool {
		current, err := os.Lstat(endpoint.path)
		return err == nil && os.SameFile(identity, current) && verifyCodingUnixSocket(endpoint.path) == nil
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !sameSocket() {
			return nil, ErrInvalidCodingUnixObserver
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", endpoint.path)
		if err != nil {
			return nil, err
		}
		if !sameSocket() {
			_ = conn.Close()
			return nil, ErrInvalidCodingUnixObserver
		}
		return conn, nil
	})
	// Recheck pathname identity even when the HTTP transport reuses a live
	// connection. Replacing the socket cannot silently select a new endpoint.
	checked := executionSocketTransport{base: base, check: sameSocket}
	bounded := &executionObservationTransport{base: checked, endpointHost: endpoint.path, binding: b, create: a, checkSocket: sameSocket}
	api, err := client.New(client.WithHost("unix://"+endpoint.path), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{
		Transport: bounded, Timeout: maxCodingObservationRequestDuration, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidCodingObservationTransport }}))
	if err != nil {
		base.CloseIdleConnections()
		return nil, ErrInvalidCodingUnixObserver
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &executionUnixObserver{gate: gate, api: api, transport: base, bounded: bounded, binding: b, create: a, documents: d, policy: policy}, nil
}

type executionSocketTransport struct {
	base  http.RoundTripper
	check func() bool
}

func (t executionSocketTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.base == nil || t.check == nil || !t.check() {
		return nil, ErrInvalidCodingUnixObserver
	}
	response, err := t.base.RoundTrip(r)
	if !t.check() {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrInvalidCodingUnixObserver
	}
	return response, err
}
func cloneExecutionDocuments(d phase6security.ImageDescriptorDocuments) phase6security.ImageDescriptorDocuments {
	return phase6security.ImageDescriptorDocuments{Index: slices.Clone(d.Index), Manifest: slices.Clone(d.Manifest), Config: slices.Clone(d.Config)}
}
func (o *executionUnixObserver) acquire(ctx context.Context) bool {
	if o == nil || o.gate == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-o.gate:
		if ctx.Err() != nil {
			o.gate <- struct{}{}
			return false
		}
		return true
	}
}
func (o *executionUnixObserver) CloseContext(ctx context.Context) error {
	if !o.acquire(ctx) {
		return ErrInvalidCodingUnixObserver
	}
	defer func() { o.gate <- struct{}{} }()
	if o.api == nil {
		return nil
	}
	if o.transport != nil {
		o.transport.CloseIdleConnections()
	}
	err := o.api.Close()
	o.api = nil
	return err
}
func (o *executionUnixObserver) observeExecutionCreate(ctx context.Context, b executionBinding, a executionCreate, revision uint64, stateDigest string) (executionCompletionObservation, error) {
	fail := func() (executionCompletionObservation, error) {
		return executionCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	if o == nil || ctx == nil || revision == 0 || !controlDigest.MatchString(stateDigest) || b.validate() != nil ||
		b.digest() != o.binding.digest() || a != o.create || a.validate(b, time.Now().UTC()) != nil || digest(o.policy) != b.Template.SeccompPolicyDigest {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !o.acquire(ctx) {
		return fail()
	}
	defer func() { o.gate <- struct{}{} }()
	if o.api == nil || o.bounded == nil || o.bounded.archiveID != "" || ctx.Err() != nil {
		return fail()
	}
	var p executionPhysicalProof
	p.Documents = cloneExecutionDocuments(o.documents)
	before, err := ObserveCodingDaemon(ctx, o.api, b.EndpointScopeDigest)
	if err != nil || before.IdentityDigest != b.DaemonDigest || before.EnvironmentDigest != b.DaemonEnvironmentDigest || before.Platform != b.Template.Image.Platform {
		return fail()
	}
	p.DaemonBefore = before
	p.InitialInventory, err = readExecutionInventory(ctx, o.api, b, a, p.Documents)
	if err != nil || p.InitialInventory.Containers[0].Present || !p.InitialInventory.Containers[1].Present {
		return fail()
	}
	r := a.resources(b)
	id := p.InitialInventory.Containers[1].ID
	labels, err := executionContainerLabels(b, a, "resident", p.Documents)
	if err != nil {
		return fail()
	}
	initial, err := o.api.ContainerInspect(ctx, r.Resident, client.ContainerInspectOptions{})
	if err != nil {
		return fail()
	}
	p.InitialRuntime, err = projectExecutionRuntime(initial.Container)
	if err != nil || p.InitialRuntime.recheck(b, a, id, labels) != nil {
		return fail()
	}
	p.InitialRuntimeDigest = executionDigest("runtime-raw", initial.Raw)
	i := b.Template.Image
	var indexRaw, selectedRaw bytes.Buffer
	index, err := o.api.ImageInspect(ctx, i.Reference, client.ImageInspectWithRawResponse(&indexRaw))
	if err != nil || index.Descriptor == nil || index.Descriptor.Digest.String() != i.Descriptor.Digest || index.Descriptor.Size != i.Descriptor.Size {
		return fail()
	}
	platform, ok := codingOCIPlatform(i.Platform)
	if !ok {
		return fail()
	}
	selected, err := o.api.ImageInspect(ctx, i.Reference, client.ImageInspectWithPlatform(&platform), client.ImageInspectWithRawResponse(&selectedRaw))
	if err != nil || !validExecutionSelectedImage(selected, b) {
		return fail()
	}
	p.SelectedImageDigest = executionDigest("selected-image-raw", selectedRaw.Bytes())
	p.Image, err = phase6security.ObserveDockerRuntimeImage(codingInspectArray(initial.Raw), codingInspectArray(indexRaw.Bytes()), i.Location, i.IdentityKind, i.Reference, i.Descriptor.Digest, i.Platform, i.SelectedManifestDigest, i.ConfigDigest, p.Documents)
	if err != nil || p.Image.ContainerID != id {
		return fail()
	}
	o.bounded.archiveID = id
	defer func() { o.bounded.archiveID = "" }()
	var rootDigests [4]string
	for n, target := range executionTargets {
		result, err := o.api.CopyFromContainer(ctx, id, client.CopyFromContainerOptions{SourcePath: target})
		if err != nil || result.Content == nil {
			return fail()
		}
		d, readErr := io.ReadAll(io.LimitReader(result.Content, maxCodingArchiveResponseBytes+1))
		closeErr := result.Content.Close()
		if readErr != nil || closeErr != nil || len(d) > maxCodingArchiveResponseBytes {
			return fail()
		}
		header, err := tar.NewReader(bytes.NewReader(d)).Next()
		if err != nil {
			return fail()
		}
		rootDigests[n] = executionDigest("empty-root-raw", d)
		p.Roots[n] = codingEmptyRootObservation{Target: target, StatName: result.Stat.Name, StatMode: uint32(result.Stat.Mode), StatSize: result.Stat.Size,
			ArchiveName: header.Name, ArchiveUID: header.Uid, ArchiveGID: header.Gid, ArchiveMode: header.Mode, ArchiveSize: header.Size, ArchiveDigest: rootDigests[n]}
	}
	final, err := o.api.ContainerInspect(ctx, r.Resident, client.ContainerInspectOptions{})
	if err != nil {
		return fail()
	}
	p.FinalRuntime, err = projectExecutionRuntime(final.Container)
	if err != nil {
		return fail()
	}
	p.FinalRuntimeDigest = executionDigest("runtime-raw", final.Raw)
	p.FinalInventory, err = readExecutionInventory(ctx, o.api, b, a, p.Documents)
	if err != nil {
		return fail()
	}
	p.DaemonAfter, err = ObserveCodingDaemon(ctx, o.api, b.EndpointScopeDigest)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	result := executionCompletionObservation{Protocol: executionReceiptProtocol, BindingDigest: b.digest(), CreateDigest: a.digest(), Resources: r, ResidentID: id, ObservedAt: time.Now().UTC(), SourceRevision: revision, SourceStateDigest: stateDigest,
		ImageEvidenceDigest: executionDigest("image-evidence", struct {
			Image    phase6security.DockerImageObservation
			Selected string
		}{p.Image, p.SelectedImageDigest}), InventoryEvidenceDigest: executionDigest("inventory", p.InitialInventory), RootEvidenceDigests: rootDigests, Physical: p}
	if result.validate(b, a, time.Now().UTC()) != nil {
		return fail()
	}
	return result, nil
}
func validExecutionSelectedImage(selected client.ImageInspectResult, b executionBinding) bool {
	t := b.Template
	m, err := codingcandidate.LockedRuntime(t.Image.Platform)
	if err != nil || selected.Descriptor == nil || selected.Config == nil {
		return false
	}
	d, c := selected.Descriptor, selected.Config
	// A local manifest's image descriptor may omit Platform. Require Docker's
	// OS/arch even then, and reject a conflicting descriptor platform. The
	// collector separately checks the original config and the container's
	// selected-manifest platform; an absent platform is never a wildcard.
	if selected.ID != t.Image.Descriptor.Digest || d.Digest.String() != t.Image.Descriptor.Digest || d.Size != t.Image.SelectedManifestSize || d.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		!codingSelectedPlatformMatches(selected.Os, selected.Architecture, selected.Variant, t.Image.Platform) ||
		(d.Platform != nil && !codingSelectedPlatformMatches(d.Platform.OS, d.Platform.Architecture, d.Platform.Variant, t.Image.Platform)) {
		return false
	}
	return slices.Equal(c.Env, t.Environment) && len(c.Entrypoint) == 0 && slices.Equal(c.Cmd, m.Command) && len(c.Volumes) == 0 && c.Healthcheck == nil && c.WorkingDir == t.WorkingDirectory && c.User == m.User
}

// Keep source records caller-owned at the collector boundary.
func cloneExecutionCompletion(o executionCompletionObservation) executionCompletionObservation {
	d, _ := json.Marshal(o)
	var result executionCompletionObservation
	_ = json.Unmarshal(d, &result)
	return result
}

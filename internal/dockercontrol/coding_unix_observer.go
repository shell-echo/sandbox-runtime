package dockercontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidCodingUnixObserver = errors.New("invalid private Coding Unix Docker observer")

const (
	maxCodingObservationRequestDuration = 5 * time.Second
	maxCodingInventoryDuration          = 10 * time.Second
)

// codingBoundUnixEndpoint must eventually come only from the exact admitted
// Security Profile v2/operator configuration. It has no exported constructor:
// a caller-supplied path or digest is not an authenticated Docker endpoint.
type codingBoundUnixEndpoint struct {
	path        string
	scopeDigest string
}

// codingUnixObserver owns one immutable SDK client and its read-only,
// pre-decode bounded transport. This is a source component, not an activated
// Control service or permission for a Provider process to open Docker.
type codingUnixObserver struct {
	gate      chan struct{}
	api       *client.Client
	transport *http.Transport
	bounded   *codingObservationTransport
	binding   CodingReceiptBinding
	authority CodingCreateAuthority
	template  phase6security.CodingRuntimeTemplateV2
	documents phase6security.ImageDescriptorDocuments
	policy    []byte
	// stage is a private, gate-protected diagnostic enum for one observation.
	// It must never contain Docker paths, response bodies, or policy text.
	stage string
}

func newCodingUnixObserver(endpoint codingBoundUnixEndpoint, binding CodingReceiptBinding,
	authority CodingCreateAuthority, template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, policy []byte) (*codingUnixObserver, error) {
	policySum := sha256.Sum256(policy)
	if binding.Validate() != nil || endpoint.scopeDigest != binding.EndpointScopeDigest ||
		verifyCodingUnixSocket(endpoint.path) != nil || template.BindPlan(binding.Plan) != nil ||
		len(policy) == 0 || len(policy) > 64<<10 ||
		"sha256:"+hex.EncodeToString(policySum[:]) != template.SeccompPolicyDigest {
		return nil, ErrInvalidCodingUnixObserver
	}
	set, err := NewCodingResourceSet(binding, authority)
	if err != nil {
		return nil, ErrInvalidCodingUnixObserver
	}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		if _, err := set.ContainerLabels(role, template, documents); err != nil {
			return nil, ErrInvalidCodingUnixObserver
		}
	}
	archiveUID, archiveGID := 0, 0
	for _, slot := range template.Slots {
		if slot.ID == authority.SlotID {
			archiveUID, archiveGID = int(slot.WorkloadUID), int(slot.WorkloadGID)
		}
	}
	if archiveUID == 0 || archiveGID == 0 {
		return nil, ErrInvalidCodingUnixObserver
	}
	base := newCodingObservationHTTPTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if verifyCodingUnixSocket(endpoint.path) != nil {
			return nil, ErrInvalidCodingUnixObserver
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", endpoint.path)
	})
	bounded := &codingObservationTransport{base: base, set: set,
		endpointHost: endpoint.path, requestHost: client.DummyHost,
		imageRef: template.Image.Reference, platform: template.Image.Platform,
		archiveUID: archiveUID, archiveGID: archiveGID, archiveMode: int64(template.VolumePrepMode)}
	httpClient := &http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrInvalidCodingObservationTransport
		}}
	api, err := client.New(client.WithHost("unix://"+endpoint.path), client.WithHTTPClient(httpClient),
		client.WithAPIVersion("1.55"))
	if err != nil {
		base.CloseIdleConnections()
		return nil, ErrInvalidCodingUnixObserver
	}
	template.Command = slices.Clone(template.Command)
	template.Environment = slices.Clone(template.Environment)
	template.Mounts = slices.Clone(template.Mounts)
	template.Slots = slices.Clone(template.Slots)
	documents.Index = slices.Clone(documents.Index)
	documents.Manifest = slices.Clone(documents.Manifest)
	documents.Config = slices.Clone(documents.Config)
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &codingUnixObserver{gate: gate, api: api, transport: base, binding: binding.clone(), authority: authority,
		bounded: bounded, template: template, documents: documents, policy: slices.Clone(policy)}, nil
}

func newCodingObservationHTTPTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{Proxy: nil, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2,
		MaxResponseHeaderBytes: 16 << 10, DialContext: dial}
}

func (o *codingUnixObserver) ReadInventory(ctx context.Context) (CodingResourceInventory, error) {
	return o.readInventoryWithBudget(ctx, maxCodingInventoryDuration)
}

func (o *codingUnixObserver) readInventoryWithBudget(ctx context.Context, budget time.Duration) (CodingResourceInventory, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || budget <= 0 || budget > maxCodingInventoryDuration {
		return CodingResourceInventory{}, ErrInvalidCodingUnixObserver
	}
	// The one absolute budget begins before waiting for the single-client
	// gate; admission time cannot be added to the ten-second inventory cap.
	boundedCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if !o.acquire(boundedCtx) {
		return CodingResourceInventory{}, ErrInvalidCodingUnixObserver
	}
	defer o.release()
	if o.api == nil {
		return CodingResourceInventory{}, ErrInvalidCodingUnixObserver
	}
	if boundedCtx.Err() != nil {
		return CodingResourceInventory{}, ErrInvalidCodingUnixObserver
	}
	return readCodingResourceInventory(boundedCtx, o.api, o.binding, o.authority, o.template, o.documents)
}

func (o *codingUnixObserver) Close() error {
	if o == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxCodingInventoryDuration)
	defer cancel()
	return o.CloseContext(ctx)
}

func (o *codingUnixObserver) CloseContext(ctx context.Context) error {
	if o == nil {
		return nil
	}
	if !o.acquire(ctx) {
		return ErrInvalidCodingUnixObserver
	}
	defer o.release()
	if o.api == nil {
		return nil
	}
	o.transport.CloseIdleConnections()
	err := o.api.Close()
	o.api = nil
	if err != nil || ctx.Err() != nil {
		return ErrInvalidCodingUnixObserver
	}
	return nil
}

func (o *codingUnixObserver) acquire(ctx context.Context) bool {
	if o == nil || o.gate == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-o.gate:
		if ctx.Err() != nil {
			o.release()
			return false
		}
		return true
	}
}

func (o *codingUnixObserver) release() { o.gate <- struct{}{} }

// verifyCodingUnixSocket checks the live socket and every ancestor with
// Lstat. No path component may be a symlink or writable by a non-root
// principal. The one socket exception is exactly root:root mode 0660; this
// does not make Docker authority low privilege. Validation never repairs a
// path, changes permissions, discovers another GID, or follows a fallback.
func verifyCodingUnixSocket(socketPath string) error {
	if !validOpaqueDaemonField(socketPath, 100) || !filepath.IsAbs(socketPath) ||
		filepath.Clean(socketPath) != socketPath ||
		len(socketPath) < len("/run/a") || len(socketPath) > 100 {
		return ErrInvalidCodingUnixObserver
	}
	parents := []string{}
	for parent := filepath.Dir(socketPath); ; parent = filepath.Dir(parent) {
		parents = append(parents, parent)
		if parent == string(filepath.Separator) {
			break
		}
	}
	for _, parent := range parents {
		info, err := os.Lstat(parent)
		if err != nil || !validCodingUnixAncestor(info) {
			return ErrInvalidCodingUnixObserver
		}
	}
	info, err := os.Lstat(socketPath)
	if err != nil || !validCodingUnixSocketInfo(info) {
		return ErrInvalidCodingUnixObserver
	}
	return nil
}

func validCodingUnixAncestor(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o022 == 0 && codingRootOwned(info)
}

func validCodingUnixSocketInfo(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o660 && codingRootOwned(info)
}

func codingRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

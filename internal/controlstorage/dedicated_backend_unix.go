//go:build darwin || linux

package controlstorage

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

const DedicatedBackendProtocol = "sandbox-runtime.control-storage-fixed-loop.v1"
const DedicatedBackendBytes int64 = 1 << 30

var loopDevice = regexp.MustCompile(`^/dev/loop(0|[1-9][0-9]{0,5})$`)

// DedicatedBackend describes required kernel facts, not a caller's attestation.
// The fixed loop size bounds the entire ext4 filesystem including metadata.
// Host/daemon administrators remain trusted; this is not protection from them.
// Provisioning, exclusive Docker ownership and Profile admission are separate.
type DedicatedBackend struct {
	Protocol    string `json:"protocol"`
	Device      string `json:"device"`
	BackingFile string `json:"backing_file"`
	Bytes       int64  `json:"bytes"`
}

func (b DedicatedBackend) Validate() error {
	if b.Protocol != DedicatedBackendProtocol || !loopDevice.MatchString(b.Device) || b.Bytes != DedicatedBackendBytes ||
		!path.IsAbs(b.BackingFile) || path.Clean(b.BackingFile) != b.BackingFile || len(b.BackingFile) > 4096 ||
		!strings.HasSuffix(b.BackingFile, "/_data/receipt.ext4") || strings.ContainsAny(b.BackingFile, "\x00\r\n\t \\") {
		return ErrInvalid
	}
	return nil
}

// InitializeDedicated requires a fresh namespace. It never promotes a legacy
// file/kernel-only manifest, and does not by itself authorize runtime dispatch.
func InitializeDedicated(ctx context.Context, path string, b Binding, backend DedicatedBackend) (*Store, error) {
	if backend.Validate() != nil {
		return nil, ErrInvalid
	}
	return initializeStorage(ctx, path, b, nil, true, &backend, nil)
}

func OpenDedicated(path string, b Binding, backend DedicatedBackend) (*Store, error) {
	if backend.Validate() != nil {
		return nil, ErrInvalid
	}
	return openStorage(path, b, true, &backend, nil)
}

func (s *Store) bindDedicatedBackend(b *DedicatedBackend) error {
	if b == nil {
		return nil
	}
	if b.Validate() != nil {
		return ErrInvalid
	}
	copy := *b
	s.backend = &copy
	return nil
}

func (s *Store) checkDedicatedBackend() error {
	if s.backend == nil {
		return nil
	}
	if s.kernel == nil || s.kernel.Identity.Filesystem != "ext4" || s.kernel.Identity.SourceDigest != sum([]byte(s.backend.Device)) {
		return ErrInvalid
	}
	if s.source != nil {
		return s.source.check(s.root.Device)
	}
	return readDedicatedLoop(s.root.Device, *s.backend)
}

// ObserveDedicated returns only a digest collected from this Store's live fd.
// It holds the same mutex as writes, checks retained bytes and exact binding,
// then rechecks kernel identity. Consumers must bracket their external reads.
// The result is a current observation, never a lease against another writer.
func (s *Store) ObserveDedicated(ctx context.Context, target string, b Binding, backend DedicatedBackend) (string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source != nil || s.path != target || s.current.Binding != b || s.backend == nil || *s.backend != backend || s.inspect() != nil || s.anchor() != nil || ctx.Err() != nil {
		return "", ErrInvalid
	}
	d, _ := json.Marshal(struct {
		Binding Binding
		Kernel  kernelRootSession
		Backend DedicatedBackend
	}{b, *s.kernel, backend})
	return sum(append([]byte("sandbox-runtime/control-dedicated-observation/v1\x00"), d...)), nil
}

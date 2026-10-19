//go:build darwin || linux

package controlstorage

import (
	"context"
	"encoding/json"
)

const SourceMountPath = "/var/lib/sandbox-runtime/control-source"
const SourceProvisionProtocol = "sandbox-runtime.control-backend-source-provision.v2"

// Stable source identity is not an authorization and excludes namespace-local
// mount IDs. Only an internally opened live source session can produce it.
type sourceIdentity struct {
	VolumeBinding string   `json:"volume_binding"`
	Protocol      string   `json:"protocol"`
	SealDigest    string   `json:"seal_digest"`
	Root          identity `json:"root"`
	Image         identity `json:"image"`
	Device        uint64   `json:"loop_device"`
}

// InitializeSourceBound is a new mode, never an upgrade of an older manifest.
// expectedSeal is a requirement; it is compared with actual canonical bytes.
// This verifies source and Store kernel facts, not external Docker exclusivity.
func InitializeSourceBound(ctx context.Context, path string, b Binding, backend DedicatedBackend, expectedSeal, volumeBinding string) (*Store, error) {
	source, err := openSource(b, backend, expectedSeal, volumeBinding)
	if err != nil {
		return nil, ErrInvalid
	}
	s, err := initializeStorage(ctx, path, b, nil, true, &backend, source)
	if err != nil {
		_ = source.close()
	}
	return s, err
}

func OpenSourceBound(path string, b Binding, backend DedicatedBackend, expectedSeal, volumeBinding string) (*Store, error) {
	source, err := openSource(b, backend, expectedSeal, volumeBinding)
	if err != nil {
		return nil, ErrInvalid
	}
	s, err := openStorage(path, b, true, &backend, source)
	if err != nil {
		_ = source.close()
	}
	return s, err
}

// ObserveSourceBound brackets external Docker reads with this live, owner-locked
// source/root/namespace check. No decoded JSON can construct its source session.
func (s *Store) ObserveSourceBound(ctx context.Context, target string, b Binding, backend DedicatedBackend, expectedSeal, volumeBinding string) (string, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source == nil || s.path != target || s.current.Binding != b || s.backend == nil || *s.backend != backend || s.source.identity.SealDigest != expectedSeal || s.source.identity.VolumeBinding != volumeBinding || s.inspect() != nil || s.anchor() != nil || ctx.Err() != nil {
		return "", ErrInvalid
	}
	d, _ := json.Marshal(struct {
		Binding Binding
		Kernel  kernelRootSession
		Backend DedicatedBackend
		Source  sourceIdentity
	}{b, *s.kernel, backend, s.source.identity})
	return sum(append([]byte("sandbox-runtime/control-source-bound-observation/v2\x00"), d...)), nil
}

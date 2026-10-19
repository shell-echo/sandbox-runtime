//go:build darwin || linux

package controlstorage

import (
	"context"
	"encoding/json"
)

// SourceProbe retains read-only source/root descriptors and the shared ceremony
// lock. It never creates a namespace marker, and is not Store authorization.
// Its digest uses the same kernel/session domain as the subsequently opened Store.
type SourceProbe struct{ root *Store }

func ProbeSourceBound(ctx context.Context, path string, b Binding, backend DedicatedBackend, seal, volumes string) (*SourceProbe, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	source, e := openSource(b, backend, seal, volumes)
	if e != nil {
		return nil, ErrInvalid
	}
	s, e := openRoot(path, b)
	if e != nil {
		_ = source.close()
		return nil, e
	}
	s.source = source
	if s.bindKernelRoot(false) != nil || s.bindDedicatedBackend(&backend) != nil || s.anchor() != nil {
		_ = s.Close()
		return nil, ErrInvalid
	}
	return &SourceProbe{root: s}, nil
}
func (p *SourceProbe) Observe(ctx context.Context) (string, error) {
	if p == nil || p.root == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrInvalid
	}
	s := p.root
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.anchor() != nil || s.source == nil || s.backend == nil || s.kernel == nil {
		return "", ErrInvalid
	}
	d, _ := json.Marshal(struct {
		Binding Binding
		Kernel  kernelRootSession
		Backend DedicatedBackend
		Source  sourceIdentity
	}{s.current.Binding, *s.kernel, *s.backend, s.source.identity})
	return sum(append([]byte("sandbox-runtime/control-source-bound-observation/v2\x00"), d...)), nil
}
func (p *SourceProbe) Close() error {
	if p == nil || p.root == nil {
		return ErrInvalid
	}
	return p.root.Close()
}

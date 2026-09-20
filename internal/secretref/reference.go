// Package secretref defines the narrow reference and rotation boundary used
// by production role configuration. Plaintext credentials are never accepted
// as configuration values or returned in stable errors.
package secretref

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const MaxReferenceBytes = 512

var referencePattern = regexp.MustCompile(`^(?:file|secret|kms)://[^\x00\r\n\t ]+$`)

var (
	ErrInvalidReference = errors.New("invalid secret reference")
	ErrUnavailable      = errors.New("secret provider unavailable")
	ErrRevoked          = errors.New("secret version revoked")
	ErrExpired          = errors.New("secret version expired")
	ErrPlaintext        = errors.New("plaintext secret is not accepted")
)

type Reference string

func Parse(value string) (Reference, error) {
	if len(value) == 0 || len(value) > MaxReferenceBytes || strings.TrimSpace(value) != value || !referencePattern.MatchString(value) {
		return "", ErrInvalidReference
	}
	parsed := Reference(value)
	if err := parsed.Validate(); err != nil {
		return "", err
	}
	return parsed, nil
}

func (r Reference) Validate() error {
	if len(r) == 0 || len(r) > MaxReferenceBytes || !referencePattern.MatchString(string(r)) {
		return ErrInvalidReference
	}
	if strings.HasPrefix(string(r), "file://") {
		path := strings.TrimPrefix(string(r), "file://")
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrInvalidReference
		}
	}
	return nil
}

func (r Reference) String() string { return string(r) }

type Provider interface {
	Resolve(context.Context, Reference) ([]byte, error)
}

type FileProvider struct{ MaxBytes int64 }

func (p FileProvider) Resolve(ctx context.Context, reference Reference) ([]byte, error) {
	if ctx == nil {
		return nil, ErrUnavailable
	}
	if err := reference.Validate(); err != nil || !strings.HasPrefix(reference.String(), "file://") {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit := p.MaxBytes
	if limit < 1 || limit > 16<<20 {
		return nil, ErrUnavailable
	}
	contents, err := secretfile.Read(strings.TrimPrefix(reference.String(), "file://"), limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	return contents, nil
}

type KeyMaterial struct {
	Reference Reference
	Version   string
	Bytes     []byte
	Digest    string
}

func (m KeyMaterial) Validate() error {
	if err := m.Reference.Validate(); err != nil || strings.TrimSpace(m.Version) == "" || len(m.Version) > 128 || len(m.Bytes) < 16 || len(m.Bytes) > 4096 {
		return ErrInvalidReference
	}
	digest := sha256.Sum256(m.Bytes)
	if m.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrInvalidReference
	}
	return nil
}

type KeyProvider interface {
	ResolveKey(context.Context, Reference, string) (KeyMaterial, error)
}

type KeyState string

const (
	KeyActive  KeyState = "active"
	KeyGrace   KeyState = "grace"
	KeyRevoked KeyState = "revoked"
)

type RotationWindow struct {
	NotBefore time.Time
	NotAfter  time.Time
	State     KeyState
}

func (w RotationWindow) Validate(now time.Time) error {
	if w.NotBefore.IsZero() || w.NotAfter.IsZero() || !w.NotAfter.After(w.NotBefore) || now.IsZero() || w.State == "" {
		return ErrInvalidReference
	}
	if w.State != KeyActive && w.State != KeyGrace && w.State != KeyRevoked {
		return ErrInvalidReference
	}
	return nil
}

type RotatingKeySet struct {
	provider Provider
	clock    func() time.Time
	mu       sync.RWMutex
	entries  map[string]keyEntry
}

type keyEntry struct {
	material KeyMaterial
	window   RotationWindow
}

func NewRotatingKeySet(provider Provider, clock func() time.Time) (*RotatingKeySet, error) {
	if provider == nil || clock == nil || clock().IsZero() {
		return nil, ErrUnavailable
	}
	return &RotatingKeySet{provider: provider, clock: clock, entries: make(map[string]keyEntry)}, nil
}

func (s *RotatingKeySet) Install(material KeyMaterial, window RotationWindow) error {
	if s == nil || material.Validate() != nil || window.Validate(s.clock()) != nil {
		return ErrInvalidReference
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[material.Version]; ok {
		clear(existing.material.Bytes)
	}
	s.entries[material.Version] = keyEntry{material: KeyMaterial{Reference: material.Reference, Version: material.Version, Bytes: append([]byte(nil), material.Bytes...), Digest: material.Digest}, window: window}
	return nil
}

func (s *RotatingKeySet) Resolve(ctx context.Context, reference Reference, version string) (KeyMaterial, error) {
	if s == nil || ctx == nil || reference.Validate() != nil || strings.TrimSpace(version) == "" {
		return KeyMaterial{}, ErrUnavailable
	}
	now := s.clock()
	s.mu.RLock()
	entry, ok := s.entries[version]
	s.mu.RUnlock()
	if !ok {
		return KeyMaterial{}, ErrUnavailable
	}
	if entry.material.Reference != reference {
		return KeyMaterial{}, ErrUnavailable
	}
	if entry.window.State == KeyRevoked {
		return KeyMaterial{}, ErrRevoked
	}
	if now.Before(entry.window.NotBefore) || !now.Before(entry.window.NotAfter) {
		return KeyMaterial{}, ErrExpired
	}
	return KeyMaterial{Reference: entry.material.Reference, Version: entry.material.Version, Bytes: append([]byte(nil), entry.material.Bytes...), Digest: entry.material.Digest}, nil
}

func (s *RotatingKeySet) ResolveKey(ctx context.Context, reference Reference, version string) (KeyMaterial, error) {
	return s.Resolve(ctx, reference, version)
}

func (s *RotatingKeySet) Revoke(version string) error {
	if s == nil || version == "" {
		return ErrInvalidReference
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[version]
	if !ok {
		return ErrUnavailable
	}
	entry.window.State = KeyRevoked
	clear(entry.material.Bytes)
	entry.material.Bytes = nil
	s.entries[version] = entry
	return nil
}

// Invalidate removes a cached key version after a provider-side rotation or
// revocation. A subsequent Resolve must obtain fresh evidence from the
// provider or fail closed.
func (s *RotatingKeySet) Invalidate(version string) error {
	if s == nil || strings.TrimSpace(version) == "" {
		return ErrInvalidReference
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[version]
	if !ok {
		return ErrUnavailable
	}
	clear(entry.material.Bytes)
	delete(s.entries, version)
	return nil
}

// CachedKeyProvider bounds the lifetime of resolved key bytes in a role
// process. The cache is deliberately keyed by both opaque reference and
// version, and can be invalidated independently of its expiry timer.
type CachedKeyProvider struct {
	source KeyProvider
	now    func() time.Time
	ttl    time.Duration
	mu     sync.Mutex
	cache  map[string]cachedKey
}

type cachedKey struct {
	material KeyMaterial
	expires  time.Time
}

func NewCachedKeyProvider(source KeyProvider, ttl time.Duration, now func() time.Time) (*CachedKeyProvider, error) {
	if source == nil || now == nil || now().IsZero() || ttl <= 0 || ttl > time.Hour {
		return nil, ErrUnavailable
	}
	return &CachedKeyProvider{source: source, now: now, ttl: ttl, cache: make(map[string]cachedKey)}, nil
}

func (p *CachedKeyProvider) ResolveKey(ctx context.Context, reference Reference, version string) (KeyMaterial, error) {
	if p == nil || ctx == nil || reference.Validate() != nil || strings.TrimSpace(version) == "" {
		return KeyMaterial{}, ErrUnavailable
	}
	key := reference.String() + "#" + version
	now := p.now()
	p.mu.Lock()
	entry, ok := p.cache[key]
	if ok && now.Before(entry.expires) {
		material := cloneKeyMaterial(entry.material)
		p.mu.Unlock()
		return material, nil
	}
	if ok {
		clear(entry.material.Bytes)
		delete(p.cache, key)
	}
	p.mu.Unlock()
	material, err := p.source.ResolveKey(ctx, reference, version)
	if err != nil {
		return KeyMaterial{}, err
	}
	if err := material.Validate(); err != nil || material.Reference != reference || material.Version != version {
		return KeyMaterial{}, ErrUnavailable
	}
	p.mu.Lock()
	p.cache[key] = cachedKey{material: cloneKeyMaterial(material), expires: now.Add(p.ttl)}
	p.mu.Unlock()
	return cloneKeyMaterial(material), nil
}

func (p *CachedKeyProvider) Invalidate(reference Reference, version string) error {
	if p == nil || reference.Validate() != nil || strings.TrimSpace(version) == "" {
		return ErrInvalidReference
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := reference.String() + "#" + version
	entry, ok := p.cache[key]
	if !ok {
		return ErrUnavailable
	}
	clear(entry.material.Bytes)
	delete(p.cache, key)
	return nil
}

func cloneKeyMaterial(material KeyMaterial) KeyMaterial {
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material
}

func (m KeyMaterial) Redacted() string {
	if m.Reference == "" || m.Version == "" {
		return "[redacted key]"
	}
	return fmt.Sprintf("%s#%s", m.Reference, m.Version)
}

package secretref

import (
	"context"
	"sync"
	"time"
)

type CachedSecretProvider struct {
	source     SecretProvider
	now        func() time.Time
	ttl        time.Duration
	maxEntries int
	mu         sync.Mutex
	cache      map[string]cachedSecret
	epoch      uint64
}

type cachedSecret struct {
	material SecretMaterial
	expires  time.Time
}

func NewCachedSecretProvider(source SecretProvider, ttl time.Duration, maxEntries int, now func() time.Time) (*CachedSecretProvider, error) {
	if source == nil || now == nil || now().IsZero() || ttl < time.Second || ttl > time.Hour || maxEntries < 1 || maxEntries > 4096 {
		return nil, ErrUnavailable
	}
	return &CachedSecretProvider{source: source, now: now, ttl: ttl, maxEntries: maxEntries, cache: make(map[string]cachedSecret)}, nil
}

func (p *CachedSecretProvider) ResolveSecret(ctx context.Context, binding Binding) (SecretMaterial, error) {
	if p == nil || p.source == nil || ctx == nil || binding.Validate() != nil || binding.Kind != KindSecret {
		return SecretMaterial{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return SecretMaterial{}, err
	}
	now := p.now()
	key := binding.Digest()
	p.mu.Lock()
	if entry, ok := p.cache[key]; ok {
		if now.Before(entry.expires) && entry.material.Validate(now) == nil {
			material := cloneSecretMaterial(entry.material)
			p.mu.Unlock()
			return material, nil
		}
		entry.material.Destroy()
		delete(p.cache, key)
	}
	epoch := p.epoch
	p.mu.Unlock()
	material, err := p.source.ResolveSecret(ctx, binding)
	if err != nil {
		material.Destroy()
		return SecretMaterial{}, normalizeProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		material.Destroy()
		return SecretMaterial{}, err
	}
	if material.Binding != binding || material.Validate(now) != nil {
		material.Destroy()
		return SecretMaterial{}, ErrUnavailable
	}
	expires := now.Add(p.ttl)
	if material.Window.NotAfter.Before(expires) {
		expires = material.Window.NotAfter
	}
	p.mu.Lock()
	if p.epoch != epoch {
		p.mu.Unlock()
		material.Destroy()
		return SecretMaterial{}, ErrUnavailable
	}
	if len(p.cache) >= p.maxEntries {
		p.evictEarliestLocked()
	}
	if existing, ok := p.cache[key]; ok {
		existing.material.Destroy()
	}
	p.cache[key] = cachedSecret{material: cloneSecretMaterial(material), expires: expires}
	p.mu.Unlock()
	resolved := cloneSecretMaterial(material)
	material.Destroy()
	return resolved, nil
}

func (p *CachedSecretProvider) Invalidate(binding Binding) error {
	if p == nil || binding.Validate() != nil || binding.Kind != KindSecret {
		return ErrInvalidReference
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	key := binding.Digest()
	if entry, ok := p.cache[key]; ok {
		entry.material.Destroy()
		delete(p.cache, key)
	}
	return nil
}

func (p *CachedSecretProvider) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	for key, entry := range p.cache {
		entry.material.Destroy()
		delete(p.cache, key)
	}
}

func (p *CachedSecretProvider) evictEarliestLocked() {
	var selected string
	var earliest time.Time
	for key, entry := range p.cache {
		if selected == "" || entry.expires.Before(earliest) || (entry.expires.Equal(earliest) && key < selected) {
			selected, earliest = key, entry.expires
		}
	}
	if selected != "" {
		entry := p.cache[selected]
		entry.material.Destroy()
		delete(p.cache, selected)
	}
}

func cloneSecretMaterial(material SecretMaterial) SecretMaterial {
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material
}

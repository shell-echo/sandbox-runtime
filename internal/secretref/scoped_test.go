package secretref

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSecretBinding() Binding {
	return Binding{
		Schema:    BindingSchema,
		Kind:      KindSecret,
		Reference: Reference("secret://vault/provider/tls-key"),
		Version:   "v1",
		Purpose:   PurposeTLSPrivateKey,
		TenantID:  "tenant-a",
		Role:      RoleProvider,
	}
}

func testEnvelopeBinding() Binding {
	return Binding{
		Schema:    BindingSchema,
		Kind:      KindEnvelopeKey,
		Reference: Reference("kms://primary/recording/key"),
		Version:   "v7",
		KeyID:     "recording-primary",
		Purpose:   PurposeRecordingEnvelopeKey,
		TenantID:  "tenant-a",
		Role:      RoleProduct,
	}
}

func TestDecodeBindingRequiresCanonicalClosedDocument(t *testing.T) {
	binding := testSecretBinding()
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBinding(document)
	if err != nil || decoded != binding {
		t.Fatalf("DecodeBinding() = %#v, %v", decoded, err)
	}

	invalid := map[string][]byte{
		"empty":        nil,
		"unknown":      append(document[:len(document)-1], []byte(`,"extra":"value"}`)...),
		"duplicate":    []byte(`{"schema":"sandbox-runtime.secret-binding.v1","schema":"sandbox-runtime.secret-binding.v1","kind":"secret","reference":"secret://vault/provider/tls-key","version":"v1","key_id":"","purpose":"tls_private_key","tenant_id":"tenant-a","role":"provider"}`),
		"trailing":     append(append([]byte(nil), document...), '\n'),
		"second value": append(append([]byte(nil), document...), []byte(`{}`)...),
		"noncanonical": []byte("{\n  \"schema\": \"sandbox-runtime.secret-binding.v1\"\n}"),
		"oversized":    []byte(strings.Repeat("x", maxBindingBytes+1)),
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBinding(candidate); !errors.Is(err, ErrInvalidReference) {
				t.Fatalf("DecodeBinding() error = %v, want %v", err, ErrInvalidReference)
			}
		})
	}
}

func TestBindingRejectsScopeAndReferenceSubstitution(t *testing.T) {
	validSecret := testSecretBinding()
	validEnvelope := testEnvelopeBinding()
	if err := validSecret.Validate(); err != nil {
		t.Fatalf("secret binding: %v", err)
	}
	if err := validEnvelope.Validate(); err != nil {
		t.Fatalf("envelope binding: %v", err)
	}

	tests := map[string]Binding{
		"schema":             func() Binding { b := validSecret; b.Schema = "v2"; return b }(),
		"kind":               func() Binding { b := validSecret; b.Kind = "credential"; return b }(),
		"inline":             func() Binding { b := validSecret; b.Reference = "plaintext"; return b }(),
		"file":               func() Binding { b := validSecret; b.Reference = "file:///run/secrets/key"; return b }(),
		"userinfo":           func() Binding { b := validSecret; b.Reference = "secret://user@vault/key"; return b }(),
		"query":              func() Binding { b := validSecret; b.Reference = "secret://vault/key?v=1"; return b }(),
		"fragment":           func() Binding { b := validSecret; b.Reference = "secret://vault/key#v1"; return b }(),
		"uppercase host":     func() Binding { b := validSecret; b.Reference = "secret://Vault/key"; return b }(),
		"empty segment":      func() Binding { b := validSecret; b.Reference = "secret://vault/path//key"; return b }(),
		"too deep":           func() Binding { b := validSecret; b.Reference = "secret://vault/a/b/c/d/e"; return b }(),
		"missing version":    func() Binding { b := validSecret; b.Version = ""; return b }(),
		"secret key id":      func() Binding { b := validSecret; b.KeyID = "must-be-empty"; return b }(),
		"purpose kind":       func() Binding { b := validSecret; b.Purpose = PurposeDataEnvelopeKey; return b }(),
		"tenant":             func() Binding { b := validSecret; b.TenantID = "tenant/a"; return b }(),
		"role":               func() Binding { b := validSecret; b.Role = "scheduler"; return b }(),
		"kms scheme":         func() Binding { b := validEnvelope; b.Reference = "secret://vault/key"; return b }(),
		"kms missing key id": func() Binding { b := validEnvelope; b.KeyID = ""; return b }(),
		"kms secret purpose": func() Binding { b := validEnvelope; b.Purpose = PurposeTLSPrivateKey; return b }(),
	}
	for name, binding := range tests {
		t.Run(name, func(t *testing.T) {
			if err := binding.Validate(); !errors.Is(err, ErrInvalidReference) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidReference)
			}
			if digest := binding.Digest(); digest != "" {
				t.Fatalf("Digest() = %q, want empty", digest)
			}
		})
	}
}

func TestBindingDigestCoversEveryAuthorityDimension(t *testing.T) {
	base := testEnvelopeBinding()
	baseDigest := base.Digest()
	if baseDigest == "" {
		t.Fatal("valid binding has empty digest")
	}
	variants := []Binding{
		func() Binding { b := base; b.Reference = "kms://secondary/recording/key"; return b }(),
		func() Binding { b := base; b.Version = "v8"; return b }(),
		func() Binding { b := base; b.KeyID = "recording-secondary"; return b }(),
		func() Binding { b := base; b.Purpose = PurposeTicketEnvelopeKey; return b }(),
		func() Binding { b := base; b.TenantID = "tenant-b"; return b }(),
		func() Binding { b := base; b.Role = RoleProvider; return b }(),
	}
	for _, variant := range variants {
		if digest := variant.Digest(); digest == "" || digest == baseDigest {
			t.Fatalf("variant digest = %q, base = %q, variant = %#v", digest, baseDigest, variant)
		}
	}
	redacted := base.Redacted()
	for _, forbidden := range []string{base.Reference.String(), base.KeyID, base.TenantID} {
		if strings.Contains(redacted, forbidden) {
			t.Fatalf("Redacted() exposed %q in %q", forbidden, redacted)
		}
	}
}

func testSecretMaterial(binding Binding, value string, now time.Time) SecretMaterial {
	contents := []byte(value)
	digest := sha256.Sum256(contents)
	return SecretMaterial{
		Binding: binding,
		Bytes:   contents,
		Digest:  "sha256:" + hex.EncodeToString(digest[:]),
		Window: RotationWindow{
			NotBefore: now.Add(-time.Minute),
			NotAfter:  now.Add(time.Hour),
			State:     KeyActive,
		},
		Revision: "revision-1",
	}
}

func TestSecretMaterialRequiresActiveBoundedVerifiedValue(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	valid := testSecretMaterial(testSecretBinding(), "super-secret", now)
	if err := valid.Validate(now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]SecretMaterial{
		"wrong kind": func() SecretMaterial {
			m := valid
			m.Binding = testEnvelopeBinding()
			return m
		}(),
		"empty":    func() SecretMaterial { m := valid; m.Bytes = nil; return m }(),
		"digest":   func() SecretMaterial { m := valid; m.Digest = "sha256:" + strings.Repeat("0", 64); return m }(),
		"future":   func() SecretMaterial { m := valid; m.Window.NotBefore = now.Add(time.Second); return m }(),
		"expired":  func() SecretMaterial { m := valid; m.Window.NotAfter = now; return m }(),
		"grace":    func() SecretMaterial { m := valid; m.Window.State = KeyGrace; return m }(),
		"revoked":  func() SecretMaterial { m := valid; m.Window.State = KeyRevoked; return m }(),
		"revision": func() SecretMaterial { m := valid; m.Revision = "bad revision"; return m }(),
	}
	for name, material := range tests {
		t.Run(name, func(t *testing.T) {
			if err := material.Validate(now); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrUnavailable)
			}
		})
	}

	backing := valid.Bytes
	valid.Destroy()
	if valid.Bytes != nil {
		t.Fatal("Destroy() retained material")
	}
	for index, value := range backing {
		if value != 0 {
			t.Fatalf("Destroy() byte %d = %d, want zero", index, value)
		}
	}
}

type staticProvider struct {
	calls     int
	reference Reference
	value     []byte
	err       error
}

type directErrorProvider struct {
	value []byte
	err   error
}

func (p directErrorProvider) Resolve(context.Context, Reference) ([]byte, error) {
	return p.value, p.err
}

func (p *staticProvider) Resolve(_ context.Context, reference Reference) ([]byte, error) {
	p.calls++
	p.reference = reference
	if p.err != nil {
		return nil, p.err
	}
	return append([]byte(nil), p.value...), nil
}

func TestBoundSecretProviderAdaptsExistingProviderWithExactAuthority(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	value := []byte("provider-secret")
	digest := sha256.Sum256(value)
	expectedDigest := "sha256:" + hex.EncodeToString(digest[:])
	window := RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive}
	source := &staticProvider{value: value}
	provider, err := NewBoundSecretProvider(source, binding, window, "provider-revision-1", expectedDigest, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	material, err := provider.ResolveSecret(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if material.Binding != binding || material.Digest != expectedDigest || string(material.Bytes) != string(value) || source.reference != binding.Reference || source.calls != 1 {
		t.Fatalf("resolved material = %#v, reference = %q, calls = %d", material, source.reference, source.calls)
	}

	otherTenant := binding
	otherTenant.TenantID = "tenant-b"
	if _, err := provider.ResolveSecret(context.Background(), otherTenant); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("scope substitution error = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("scope substitution reached source; calls = %d", source.calls)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.ResolveSecret(cancelled, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("cancellation reached source; calls = %d", source.calls)
	}

	now = window.NotAfter
	if _, err := provider.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired authority error = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("expired authority reached source; calls = %d", source.calls)
	}
}

func TestBoundSecretProviderRejectsMutableReferenceAndRedactsErrors(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	want := []byte("expected-secret")
	digest := sha256.Sum256(want)
	expectedDigest := "sha256:" + hex.EncodeToString(digest[:])
	window := RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive}

	source := &staticProvider{value: []byte("substituted-secret")}
	provider, err := NewBoundSecretProvider(source, binding, window, "provider-revision-1", expectedDigest, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("digest mismatch error = %v", err)
	}

	source.err = errors.New("vault host, token, and secret path")
	if _, err := provider.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "vault") {
		t.Fatalf("provider error = %v", err)
	}

	if _, err := NewBoundSecretProvider(source, binding, window, "provider-revision-1", strings.ToUpper(expectedDigest), func() time.Time { return now }); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("noncanonical digest error = %v", err)
	}

	errorBytes := []byte("returned-with-error")
	errorProvider, err := NewBoundSecretProvider(directErrorProvider{value: errorBytes, err: errors.New("private backend details")}, binding, window, "provider-revision-1", expectedDigest, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := errorProvider.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("direct provider error = %v", err)
	}
	for index, value := range errorBytes {
		if value != 0 {
			t.Fatalf("error bytes[%d] = %d, want zero", index, value)
		}
	}
}

type fakeSecretProvider struct {
	calls    int
	material SecretMaterial
	err      error
}

type materialErrorProvider struct {
	material SecretMaterial
	err      error
}

func (p materialErrorProvider) ResolveSecret(context.Context, Binding) (SecretMaterial, error) {
	return p.material, p.err
}

type blockingSecretProvider struct {
	started  chan struct{}
	release  chan struct{}
	material SecretMaterial
}

func (p *blockingSecretProvider) ResolveSecret(context.Context, Binding) (SecretMaterial, error) {
	close(p.started)
	<-p.release
	return cloneSecretMaterial(p.material), nil
}

func (p *fakeSecretProvider) ResolveSecret(context.Context, Binding) (SecretMaterial, error) {
	p.calls++
	if p.err != nil {
		return SecretMaterial{}, p.err
	}
	return cloneSecretMaterial(p.material), nil
}

func TestCachedSecretProviderBoundsFailureCacheAndMutation(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	source := &fakeSecretProvider{material: testSecretMaterial(binding, "secret-a", now)}
	cache, err := NewCachedSecretProvider(source, time.Minute, 2, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.ResolveSecret(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	first.Bytes[0] = 'X'
	source.err = errors.New("backend details must not escape")
	second, err := cache.ResolveSecret(context.Background(), binding)
	if err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if string(second.Bytes) != "secret-a" || source.calls != 1 {
		t.Fatalf("cached material = %q, calls = %d", second.Bytes, source.calls)
	}

	now = now.Add(time.Minute)
	if _, err := cache.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "backend details") {
		t.Fatalf("expired provider error = %v", err)
	}
	if source.calls != 2 {
		t.Fatalf("provider calls = %d, want 2", source.calls)
	}

	source.err = nil
	if err := cache.Invalidate(binding); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveSecret(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if source.calls != 3 {
		t.Fatalf("provider calls after invalidation = %d, want 3", source.calls)
	}
	cache.Close()
	if _, err := cache.ResolveSecret(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if source.calls != 4 {
		t.Fatalf("provider calls after Close = %d, want 4", source.calls)
	}
}

func TestCachedSecretProviderPreservesCancellation(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	source := &fakeSecretProvider{material: testSecretMaterial(binding, "secret-a", now)}
	cache, err := NewCachedSecretProvider(source, time.Minute, 2, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.ResolveSecret(ctx, binding); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSecret() error = %v, want %v", err, context.Canceled)
	}
	if source.calls != 0 {
		t.Fatalf("cancelled request reached source; calls = %d", source.calls)
	}
}

func TestCachedSecretProviderClearsMaterialReturnedWithError(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	material := testSecretMaterial(binding, "must-be-cleared", now)
	backing := material.Bytes
	cache, err := NewCachedSecretProvider(materialErrorProvider{material: material, err: errors.New("provider failure")}, time.Minute, 2, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveSecret(context.Background(), binding); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ResolveSecret() error = %v, want %v", err, ErrUnavailable)
	}
	for index, value := range backing {
		if value != 0 {
			t.Fatalf("error material byte %d = %d, want zero", index, value)
		}
	}
}

func TestCachedSecretProviderDoesNotReinsertAfterInvalidation(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	binding := testSecretBinding()
	source := &blockingSecretProvider{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		material: testSecretMaterial(binding, "secret-a", now),
	}
	cache, err := NewCachedSecretProvider(source, time.Minute, 2, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, resolveErr := cache.ResolveSecret(context.Background(), binding)
		result <- resolveErr
	}()
	<-source.started
	if err := cache.Invalidate(binding); err != nil {
		t.Fatal(err)
	}
	close(source.release)
	if err := <-result; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("in-flight resolution error = %v, want %v", err, ErrUnavailable)
	}

	replacement := &fakeSecretProvider{material: testSecretMaterial(binding, "secret-b", now)}
	cache.source = replacement
	material, err := cache.ResolveSecret(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if string(material.Bytes) != "secret-b" || replacement.calls != 1 {
		t.Fatalf("post-invalidation material = %q, calls = %d", material.Bytes, replacement.calls)
	}
}

func TestCachedSecretProviderRejectsScopeMismatchAndBoundsCapacity(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	bindingA := testSecretBinding()
	bindingB := bindingA
	bindingB.TenantID = "tenant-b"
	source := &fakeSecretProvider{material: testSecretMaterial(bindingB, "secret-b", now)}
	cache, err := NewCachedSecretProvider(source, time.Minute, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveSecret(context.Background(), bindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("scope mismatch error = %v", err)
	}

	source.material = testSecretMaterial(bindingA, "secret-a", now)
	if _, err := cache.ResolveSecret(context.Background(), bindingA); err != nil {
		t.Fatal(err)
	}
	source.material = testSecretMaterial(bindingB, "secret-b", now)
	if _, err := cache.ResolveSecret(context.Background(), bindingB); err != nil {
		t.Fatal(err)
	}
	source.material = testSecretMaterial(bindingA, "secret-a", now)
	if _, err := cache.ResolveSecret(context.Background(), bindingA); err != nil {
		t.Fatal(err)
	}
	if source.calls != 4 {
		t.Fatalf("provider calls = %d, want mismatch plus three bounded resolutions", source.calls)
	}
}

type fakeEnvelopeProvider struct {
	seal      func(Binding, []byte, []byte) (OpaqueEnvelope, error)
	open      func(Binding, OpaqueEnvelope, []byte) ([]byte, error)
	sealCalls int
	openCalls int
}

func (p *fakeEnvelopeProvider) SealEnvelope(_ context.Context, binding Binding, plaintext, associatedData []byte) (OpaqueEnvelope, error) {
	p.sealCalls++
	return p.seal(binding, plaintext, associatedData)
}

func (p *fakeEnvelopeProvider) OpenEnvelope(_ context.Context, binding Binding, envelope OpaqueEnvelope, associatedData []byte) ([]byte, error) {
	p.openCalls++
	return p.open(binding, envelope, associatedData)
}

func validOpaqueEnvelope(binding Binding, ciphertext []byte) OpaqueEnvelope {
	return OpaqueEnvelope{
		BindingDigest: binding.Digest(),
		KeyID:         binding.KeyID,
		KeyVersion:    binding.Version,
		Algorithm:     EnvelopeAlgorithmV1,
		Ciphertext:    append([]byte(nil), ciphertext...),
	}
}

func TestBoundEnvelopeKeyProviderEnforcesOpaqueBinding(t *testing.T) {
	binding := testEnvelopeBinding()
	wantAAD := "tenant-a/recording-1"
	source := &fakeEnvelopeProvider{}
	source.seal = func(got Binding, plaintext, associatedData []byte) (OpaqueEnvelope, error) {
		if got != binding || string(associatedData) != wantAAD {
			return OpaqueEnvelope{}, errors.New("unexpected scope")
		}
		return validOpaqueEnvelope(got, append([]byte("sealed:"), plaintext...)), nil
	}
	source.open = func(got Binding, envelope OpaqueEnvelope, associatedData []byte) ([]byte, error) {
		if got != binding || string(associatedData) != wantAAD || !strings.HasPrefix(string(envelope.Ciphertext), "sealed:") {
			return nil, ErrUnavailable
		}
		return append([]byte(nil), envelope.Ciphertext[len("sealed:"):]...), nil
	}
	provider, err := NewBoundEnvelopeKeyProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := provider.SealEnvelope(context.Background(), binding, []byte("payload"), []byte(wantAAD))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := provider.OpenEnvelope(context.Background(), binding, envelope, []byte(wantAAD))
	if err != nil || string(plaintext) != "payload" {
		t.Fatalf("OpenEnvelope() = %q, %v", plaintext, err)
	}
	if source.sealCalls != 1 || source.openCalls != 1 {
		t.Fatalf("calls = seal %d, open %d", source.sealCalls, source.openCalls)
	}
}

func TestBoundEnvelopeKeyProviderRejectsMismatchesAndNormalizesErrors(t *testing.T) {
	binding := testEnvelopeBinding()
	aad := []byte("tenant-a/data-1")
	tests := map[string]func(*OpaqueEnvelope){
		"binding digest": func(e *OpaqueEnvelope) { e.BindingDigest = strings.Repeat("0", 64) },
		"key id":         func(e *OpaqueEnvelope) { e.KeyID = "other" },
		"key version":    func(e *OpaqueEnvelope) { e.KeyVersion = "v8" },
		"algorithm":      func(e *OpaqueEnvelope) { e.Algorithm = "unknown" },
		"ciphertext":     func(e *OpaqueEnvelope) { e.Ciphertext = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			source := &fakeEnvelopeProvider{
				seal: func(got Binding, _, _ []byte) (OpaqueEnvelope, error) {
					envelope := validOpaqueEnvelope(got, []byte("ciphertext"))
					mutate(&envelope)
					return envelope, nil
				},
				open: func(Binding, OpaqueEnvelope, []byte) ([]byte, error) { return []byte("unused"), nil },
			}
			provider, err := NewBoundEnvelopeKeyProvider(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.SealEnvelope(context.Background(), binding, []byte("payload"), aad); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("SealEnvelope() error = %v, want %v", err, ErrUnavailable)
			}
		})
	}

	sealedErrorBytes := []byte("sealed-error-bytes")
	openedErrorBytes := []byte("opened-error-bytes")
	source := &fakeEnvelopeProvider{
		seal: func(Binding, []byte, []byte) (OpaqueEnvelope, error) {
			return OpaqueEnvelope{Ciphertext: sealedErrorBytes}, ErrRevoked
		},
		open: func(Binding, OpaqueEnvelope, []byte) ([]byte, error) {
			return openedErrorBytes, errors.New("kms endpoint and key details")
		},
	}
	provider, err := NewBoundEnvelopeKeyProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.SealEnvelope(context.Background(), binding, []byte("payload"), aad); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked error = %v", err)
	}
	for index, value := range sealedErrorBytes {
		if value != 0 {
			t.Fatalf("sealed error bytes[%d] = %d, want zero", index, value)
		}
	}
	valid := validOpaqueEnvelope(binding, []byte("ciphertext"))
	if _, err := provider.OpenEnvelope(context.Background(), binding, valid, aad); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "kms endpoint") {
		t.Fatalf("normalized error = %v", err)
	}
	for index, value := range openedErrorBytes {
		if value != 0 {
			t.Fatalf("opened error bytes[%d] = %d, want zero", index, value)
		}
	}

	if _, err := provider.SealEnvelope(context.Background(), binding, []byte("payload"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty AAD error = %v", err)
	}
	if source.sealCalls != 1 {
		t.Fatalf("invalid AAD reached source; calls = %d", source.sealCalls)
	}
	wrongBinding := binding
	wrongBinding.TenantID = "tenant-b"
	if _, err := provider.OpenEnvelope(context.Background(), wrongBinding, valid, aad); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("scope substitution error = %v", err)
	}
	if source.openCalls != 1 {
		t.Fatalf("invalid envelope reached source; calls = %d", source.openCalls)
	}
}

func TestBoundEnvelopeKeyProviderRejectsBoundsAndCancellation(t *testing.T) {
	binding := testEnvelopeBinding()
	source := &fakeEnvelopeProvider{
		seal: func(got Binding, plaintext, _ []byte) (OpaqueEnvelope, error) {
			return validOpaqueEnvelope(got, plaintext), nil
		},
		open: func(Binding, OpaqueEnvelope, []byte) ([]byte, error) { return []byte("plaintext"), nil },
	}
	provider, err := NewBoundEnvelopeKeyProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("tenant-a/data-1")
	if _, err := provider.SealEnvelope(context.Background(), binding, make([]byte, MaxPlaintextBytes+1), aad); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized plaintext error = %v", err)
	}
	if _, err := provider.SealEnvelope(context.Background(), binding, []byte("payload"), make([]byte, MaxAssociatedDataBytes+1)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized AAD error = %v", err)
	}
	if source.sealCalls != 0 {
		t.Fatalf("invalid bounds reached source; calls = %d", source.sealCalls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.SealEnvelope(ctx, binding, []byte("payload"), aad); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if source.sealCalls != 0 {
		t.Fatalf("cancelled seal reached source; calls = %d", source.sealCalls)
	}

	oversized := validOpaqueEnvelope(binding, make([]byte, MaxEnvelopeBytes+1))
	if _, err := provider.OpenEnvelope(context.Background(), binding, oversized, aad); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized envelope error = %v", err)
	}
	if source.openCalls != 0 {
		t.Fatalf("oversized envelope reached source; calls = %d", source.openCalls)
	}
}

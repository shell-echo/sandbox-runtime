package secretref

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	BindingSchema          = "sandbox-runtime.secret-binding.v1"
	MaxSecretBytes         = 1 << 20
	MaxEnvelopeBytes       = MaxPlaintextBytes + 64<<10
	MaxAssociatedDataBytes = 64 << 10
	SystemTenant           = "_system"
	EnvelopeAlgorithmV1    = "kms-envelope-v1"
	maxBindingBytes        = 4 << 10
)

type MaterialKind string

const (
	KindSecret      MaterialKind = "secret"
	KindEnvelopeKey MaterialKind = "envelope_key"
)

type Role string

const (
	RoleProduct  Role = "product"
	RoleProvider Role = "provider"
	RoleGateway  Role = "gateway"
	RoleGuest    Role = "guest"
	RoleBrowser  Role = "browser"
	RoleDesktop  Role = "desktop"
)

type Purpose string

const (
	PurposeTLSCertificate        Purpose = "tls_certificate"
	PurposeTLSPrivateKey         Purpose = "tls_private_key"
	PurposeCABundle              Purpose = "ca_bundle"
	PurposePostgresMigrationDSN  Purpose = "postgres_migration_dsn"
	PurposePostgresRuntimeDSN    Purpose = "postgres_runtime_dsn"
	PurposeIdentityKeyRing       Purpose = "identity_key_ring"
	PurposeAdmissionVerification Purpose = "admission_verification_key"
	PurposeCoordinationEndpoint  Purpose = "coordination_endpoint"
	PurposeCoordinationIdentity  Purpose = "coordination_identity"
	PurposeObjectStoreEndpoint   Purpose = "object_store_endpoint"
	PurposeObjectStoreIdentity   Purpose = "object_store_identity"
	PurposeKMSEndpoint           Purpose = "kms_endpoint"
	PurposeKMSIdentity           Purpose = "kms_identity"
	PurposeWorkloadCredential    Purpose = "workload_credential"
	PurposeGatewayGrantKey       Purpose = "gateway_grant_key"
	PurposeGuestSigningKey       Purpose = "guest_signing_key"
	PurposeExecutorClientKey     Purpose = "executor_client_key"
	PurposeExecutorBridgeKey     Purpose = "executor_bridge_signing_key"
	PurposeRecordingEnvelopeKey  Purpose = "recording_envelope_key"
	PurposeTicketEnvelopeKey     Purpose = "ticket_envelope_key"
	PurposeDataEnvelopeKey       Purpose = "data_envelope_key"
)

var (
	scopedNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	scopedVersionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	scopedTenantPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

	secretPurposes = map[Purpose]struct{}{
		PurposeTLSCertificate: {}, PurposeTLSPrivateKey: {}, PurposeCABundle: {},
		PurposePostgresMigrationDSN: {}, PurposePostgresRuntimeDSN: {}, PurposeIdentityKeyRing: {},
		PurposeAdmissionVerification: {}, PurposeCoordinationEndpoint: {}, PurposeCoordinationIdentity: {},
		PurposeObjectStoreEndpoint: {}, PurposeObjectStoreIdentity: {}, PurposeKMSEndpoint: {}, PurposeKMSIdentity: {},
		PurposeWorkloadCredential: {}, PurposeGatewayGrantKey: {}, PurposeGuestSigningKey: {},
		PurposeExecutorClientKey: {}, PurposeExecutorBridgeKey: {},
	}
	envelopePurposes = map[Purpose]struct{}{
		PurposeRecordingEnvelopeKey: {}, PurposeTicketEnvelopeKey: {}, PurposeDataEnvelopeKey: {},
	}
)

// Binding is the complete non-secret authority required for one resolution.
// Scope is explicit and cannot be inferred from a reference returned by a
// provider.
type Binding struct {
	Schema    string       `json:"schema"`
	Kind      MaterialKind `json:"kind"`
	Reference Reference    `json:"reference"`
	Version   string       `json:"version"`
	KeyID     string       `json:"key_id"`
	Purpose   Purpose      `json:"purpose"`
	TenantID  string       `json:"tenant_id"`
	Role      Role         `json:"role"`
}

func DecodeBinding(document []byte) (Binding, error) {
	if len(document) == 0 || len(document) > maxBindingBytes {
		return Binding{}, ErrInvalidReference
	}
	unique := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueBindingJSON(unique); err != nil {
		return Binding{}, ErrInvalidReference
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var binding Binding
	if err := decoder.Decode(&binding); err != nil {
		return Binding{}, ErrInvalidReference
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Binding{}, ErrInvalidReference
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(document, canonical) || binding.Validate() != nil {
		return Binding{}, ErrInvalidReference
	}
	return binding, nil
}

func (b Binding) Validate() error {
	if b.Schema != BindingSchema || !validScopedRole(b.Role) || !validScopedTenant(b.TenantID) ||
		!scopedVersionPattern.MatchString(b.Version) || !validScopedReference(b.Reference) {
		return ErrInvalidReference
	}
	parsed, _ := url.Parse(b.Reference.String())
	switch b.Kind {
	case KindSecret:
		if parsed.Scheme != "secret" || b.KeyID != "" {
			return ErrInvalidReference
		}
		if _, ok := secretPurposes[b.Purpose]; !ok {
			return ErrInvalidReference
		}
	case KindEnvelopeKey:
		if parsed.Scheme != "kms" || !scopedNamePattern.MatchString(b.KeyID) {
			return ErrInvalidReference
		}
		if _, ok := envelopePurposes[b.Purpose]; !ok {
			return ErrInvalidReference
		}
	default:
		return ErrInvalidReference
	}
	return nil
}

func (b Binding) Digest() string {
	if b.Validate() != nil {
		return ""
	}
	document, _ := json.Marshal(b)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/secret-binding/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (b Binding) Redacted() string {
	digest := b.Digest()
	if digest == "" {
		return "[redacted secret binding]"
	}
	return "secret-binding:" + digest
}

func validScopedReference(reference Reference) bool {
	if reference.Validate() != nil || len(reference) > MaxReferenceBytes {
		return false
	}
	parsed, err := url.Parse(reference.String())
	if err != nil || (parsed.Scheme != "secret" && parsed.Scheme != "kms") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || !scopedNamePattern.MatchString(parsed.Host) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) < 1 || len(segments) > 4 {
		return false
	}
	for _, segment := range segments {
		if !scopedNamePattern.MatchString(segment) {
			return false
		}
	}
	return parsed.String() == reference.String()
}

func validScopedRole(role Role) bool {
	switch role {
	case RoleProduct, RoleProvider, RoleGateway, RoleGuest, RoleBrowser, RoleDesktop:
		return true
	default:
		return false
	}
}

func validScopedTenant(tenant string) bool {
	return tenant == SystemTenant || scopedTenantPattern.MatchString(tenant)
}

type SecretMaterial struct {
	Binding  Binding
	Bytes    []byte
	Digest   string
	Window   RotationWindow
	Revision string
}

func (m SecretMaterial) Validate(now time.Time) error {
	if m.Binding.Validate() != nil || m.Binding.Kind != KindSecret || now.IsZero() ||
		len(m.Bytes) == 0 || len(m.Bytes) > MaxSecretBytes || !scopedVersionPattern.MatchString(m.Revision) ||
		m.Window.Validate(now) != nil || now.Before(m.Window.NotBefore) || !now.Before(m.Window.NotAfter) || m.Window.State != KeyActive {
		return ErrUnavailable
	}
	digest := sha256.Sum256(m.Bytes)
	if m.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrUnavailable
	}
	return nil
}

func (m *SecretMaterial) Destroy() {
	if m == nil {
		return
	}
	clear(m.Bytes)
	m.Bytes = nil
}

type SecretProvider interface {
	ResolveSecret(context.Context, Binding) (SecretMaterial, error)
}

// BoundSecretProvider adapts the repository's existing Provider port to one
// exact scoped and versioned binding. The expected digest is non-secret
// integrity metadata and prevents a mutable reference from silently serving a
// different version. Rotation installs a new adapter; it does not mutate this
// authority in place.
type BoundSecretProvider struct {
	source         Provider
	binding        Binding
	window         RotationWindow
	revision       string
	expectedDigest string
	now            func() time.Time
}

func NewBoundSecretProvider(source Provider, binding Binding, window RotationWindow, revision, expectedDigest string, now func() time.Time) (*BoundSecretProvider, error) {
	if source == nil || binding.Validate() != nil || binding.Kind != KindSecret || now == nil {
		return nil, ErrUnavailable
	}
	current := now()
	if current.IsZero() || window.Validate(current) != nil || window.State != KeyActive || current.Before(window.NotBefore) || !current.Before(window.NotAfter) ||
		!scopedVersionPattern.MatchString(revision) || !validSHA256Digest(expectedDigest) {
		return nil, ErrUnavailable
	}
	return &BoundSecretProvider{
		source:         source,
		binding:        binding,
		window:         window,
		revision:       revision,
		expectedDigest: expectedDigest,
		now:            now,
	}, nil
}

func (p *BoundSecretProvider) ResolveSecret(ctx context.Context, binding Binding) (SecretMaterial, error) {
	if p == nil || p.source == nil || ctx == nil || binding != p.binding || binding.Validate() != nil {
		return SecretMaterial{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return SecretMaterial{}, err
	}
	now := p.now()
	if p.window.Validate(now) != nil || p.window.State != KeyActive || now.Before(p.window.NotBefore) || !now.Before(p.window.NotAfter) {
		return SecretMaterial{}, ErrExpired
	}
	contents, err := p.source.Resolve(ctx, binding.Reference)
	if err != nil {
		clear(contents)
		return SecretMaterial{}, normalizeProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		clear(contents)
		return SecretMaterial{}, err
	}
	material := SecretMaterial{
		Binding:  binding,
		Bytes:    contents,
		Digest:   p.expectedDigest,
		Window:   p.window,
		Revision: p.revision,
	}
	if material.Validate(now) != nil {
		material.Destroy()
		return SecretMaterial{}, ErrUnavailable
	}
	return material, nil
}

type OpaqueEnvelope struct {
	BindingDigest string `json:"binding_digest"`
	KeyID         string `json:"key_id"`
	KeyVersion    string `json:"key_version"`
	Algorithm     string `json:"algorithm"`
	Ciphertext    []byte `json:"ciphertext"`
}

func (e OpaqueEnvelope) Validate(binding Binding) error {
	if binding.Validate() != nil || binding.Kind != KindEnvelopeKey || e.BindingDigest != binding.Digest() ||
		e.KeyID != binding.KeyID || e.KeyVersion != binding.Version || e.Algorithm != EnvelopeAlgorithmV1 || len(e.Ciphertext) == 0 || len(e.Ciphertext) > MaxEnvelopeBytes {
		return ErrInvalidEnvelope
	}
	return nil
}

type EnvelopeKeyProvider interface {
	SealEnvelope(context.Context, Binding, []byte, []byte) (OpaqueEnvelope, error)
	OpenEnvelope(context.Context, Binding, OpaqueEnvelope, []byte) ([]byte, error)
}

// BoundEnvelopeKeyProvider closes scope substitution around an external KMS or
// HSM adapter. The adapter retains key bytes and returns only an opaque envelope.
type BoundEnvelopeKeyProvider struct{ source EnvelopeKeyProvider }

func NewBoundEnvelopeKeyProvider(source EnvelopeKeyProvider) (*BoundEnvelopeKeyProvider, error) {
	if source == nil {
		return nil, ErrUnavailable
	}
	return &BoundEnvelopeKeyProvider{source: source}, nil
}

func (p *BoundEnvelopeKeyProvider) SealEnvelope(ctx context.Context, binding Binding, plaintext, associatedData []byte) (OpaqueEnvelope, error) {
	if p == nil || p.source == nil || ctx == nil || binding.Validate() != nil || binding.Kind != KindEnvelopeKey || len(plaintext) > MaxPlaintextBytes || len(associatedData) == 0 || len(associatedData) > MaxAssociatedDataBytes {
		return OpaqueEnvelope{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return OpaqueEnvelope{}, err
	}
	envelope, err := p.source.SealEnvelope(ctx, binding, plaintext, associatedData)
	if err != nil {
		clear(envelope.Ciphertext)
		return OpaqueEnvelope{}, normalizeProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		clear(envelope.Ciphertext)
		return OpaqueEnvelope{}, err
	}
	if envelope.Validate(binding) != nil {
		return OpaqueEnvelope{}, ErrUnavailable
	}
	return cloneEnvelope(envelope), nil
}

func (p *BoundEnvelopeKeyProvider) OpenEnvelope(ctx context.Context, binding Binding, envelope OpaqueEnvelope, associatedData []byte) ([]byte, error) {
	if p == nil || p.source == nil || ctx == nil || envelope.Validate(binding) != nil || len(associatedData) == 0 || len(associatedData) > MaxAssociatedDataBytes {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plaintext, err := p.source.OpenEnvelope(ctx, binding, cloneEnvelope(envelope), associatedData)
	if err != nil {
		clear(plaintext)
		return nil, normalizeProviderError(err)
	}
	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}
	if len(plaintext) > MaxPlaintextBytes {
		clear(plaintext)
		return nil, ErrUnavailable
	}
	return plaintext, nil
}

func cloneEnvelope(value OpaqueEnvelope) OpaqueEnvelope {
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	return value
}

func normalizeProviderError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrRevoked):
		return ErrRevoked
	case errors.Is(err, ErrExpired):
		return ErrExpired
	default:
		return ErrUnavailable
	}
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func scanUniqueBindingJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	object, ok := token.(json.Delim)
	if !ok || object != '{' {
		return ErrInvalidReference
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return ErrInvalidReference
		}
		if _, exists := seen[key]; exists {
			return ErrInvalidReference
		}
		seen[key] = struct{}{}
		if err := skipBindingJSONValue(decoder); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidReference
	}
	return nil
}

func skipBindingJSONValue(decoder *json.Decoder) error {
	var value any
	return decoder.Decode(&value)
}

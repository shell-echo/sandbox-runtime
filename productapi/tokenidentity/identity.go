// Package tokenidentity verifies the closed, operator-pinned Product access
// token format used by the production Product process.
package tokenidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const (
	KeyRingVersion      = "sandbox-runtime-product-access-key-ring-v1"
	expectedTokenType   = "sandbox-runtime-product-access+jwt"
	maxKeyRingBytes     = 256 << 10
	maxCompactTokenSize = 8 << 10
	maxKeys             = 32
)

var requiredClaims = [...]string{"iss", "aud", "sub", "tenant_id", "actor_type", "actor_id", "role", "iat", "nbf", "exp", "jti"}

type keyRingDocument struct {
	Version       string        `json:"version"`
	Keys          []keyDocument `json:"keys"`
	RevokedKeyIDs []string      `json:"revoked_key_ids"`
}

type keyDocument struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type tokenClaims struct {
	Issuer    string            `json:"iss"`
	Audience  string            `json:"aud"`
	Subject   string            `json:"sub"`
	TenantID  string            `json:"tenant_id"`
	ActorType product.ActorType `json:"actor_type"`
	ActorID   string            `json:"actor_id"`
	Role      productapi.Role   `json:"role"`
	IssuedAt  int64             `json:"iat"`
	NotBefore int64             `json:"nbf"`
	ExpiresAt int64             `json:"exp"`
	JTI       string            `json:"jti"`
}

type trustedKey struct {
	publicKey ed25519.PublicKey
	notBefore time.Time
	notAfter  time.Time
	revoked   bool
}

// Clock permits deterministic time-window and key-overlap tests.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Authenticator is an immutable key-ring verifier. Key rotation is performed
// by deploying an overlapping ring, replacing processes, then revoking the old
// key in a later ring revision.
type Authenticator struct {
	issuer      string
	audience    string
	clockSkew   time.Duration
	maxLifetime time.Duration
	clock       Clock
	keys        map[string]trustedKey
}

// Load reads a strict mode-0600 key ring and freezes it for this process.
func Load(path, issuer, audience string, clockSkew, maxLifetime time.Duration) (*Authenticator, error) {
	return load(path, issuer, audience, clockSkew, maxLifetime, systemClock{})
}

// LoadMaterial freezes one caller-owned, bounded key-ring document resolved
// through the production material registry. The caller remains responsible for
// clearing the source bytes after this function returns.
func LoadMaterial(document []byte, issuer, audience string, clockSkew, maxLifetime time.Duration) (*Authenticator, error) {
	return loadMaterial(document, issuer, audience, clockSkew, maxLifetime, systemClock{})
}

func load(path, issuer, audience string, clockSkew, maxLifetime time.Duration, clock Clock) (*Authenticator, error) {
	raw, err := secretfile.Read(path, maxKeyRingBytes)
	if err != nil {
		return nil, errors.New("load Product token verification key ring")
	}
	defer clear(raw)
	return loadMaterial(raw, issuer, audience, clockSkew, maxLifetime, clock)
}

func loadMaterial(raw []byte, issuer, audience string, clockSkew, maxLifetime time.Duration, clock Clock) (*Authenticator, error) {
	if !validIssuer(issuer) || !validAbsoluteURI(audience) || clock == nil || clockSkew < 0 || clockSkew > 2*time.Minute ||
		maxLifetime < time.Minute || maxLifetime > time.Hour {
		return nil, errors.New("invalid Product token identity policy")
	}
	if len(raw) < 1 || len(raw) > maxKeyRingBytes {
		return nil, errors.New("invalid Product token verification key ring")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document keyRingDocument
	if err := decoder.Decode(&document); err != nil || requireEOF(decoder) != nil || document.Version != KeyRingVersion ||
		len(document.Keys) < 1 || len(document.Keys) > maxKeys || len(document.RevokedKeyIDs) > maxKeys {
		return nil, errors.New("invalid Product token verification key ring")
	}
	revoked := make(map[string]struct{}, len(document.RevokedKeyIDs))
	for _, keyID := range document.RevokedKeyIDs {
		if !validText(keyID, 1, 128) {
			return nil, errors.New("invalid Product token verification key ring")
		}
		if _, exists := revoked[keyID]; exists {
			return nil, errors.New("invalid Product token verification key ring")
		}
		revoked[keyID] = struct{}{}
	}
	keys := make(map[string]trustedKey, len(document.Keys))
	for _, item := range document.Keys {
		if !validText(item.KeyID, 1, 128) || item.Algorithm != "EdDSA" {
			return nil, errors.New("invalid Product token verification key ring")
		}
		if _, exists := keys[item.KeyID]; exists {
			return nil, errors.New("invalid Product token verification key ring")
		}
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(item.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Product token verification key ring")
		}
		notBefore, errBefore := time.Parse(time.RFC3339, item.NotBefore)
		notAfter, errAfter := time.Parse(time.RFC3339, item.NotAfter)
		if errBefore != nil || errAfter != nil || !notAfter.After(notBefore) {
			return nil, errors.New("invalid Product token verification key ring")
		}
		_, isRevoked := revoked[item.KeyID]
		keys[item.KeyID] = trustedKey{publicKey: ed25519.PublicKey(append([]byte(nil), publicKey...)), notBefore: notBefore, notAfter: notAfter, revoked: isRevoked}
	}
	for keyID := range revoked {
		if _, exists := keys[keyID]; !exists {
			return nil, errors.New("invalid Product token verification key ring")
		}
	}
	return &Authenticator{issuer: issuer, audience: audience, clockSkew: clockSkew, maxLifetime: maxLifetime, clock: clock, keys: keys}, nil
}

// Authenticate verifies the closed JWT header/claims shape, exact issuer and
// audience, active non-revoked key, bounded lifetime, and Ed25519 signature.
func (a *Authenticator) Authenticate(ctx context.Context, compact string) (productapi.Principal, error) {
	if a == nil || ctx == nil || len(compact) == 0 || len(compact) > maxCompactTokenSize {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return productapi.Principal{}, err
	}
	segments := strings.Split(compact, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	headerBytes, headerOK := decodeSegment(segments[0])
	claimsBytes, claimsOK := decodeSegment(segments[1])
	signature, signatureOK := decodeSegment(segments[2])
	if !headerOK || !claimsOK || !signatureOK || len(signature) != ed25519.SignatureSize {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	var header tokenHeader
	if !decodeClosed(headerBytes, &header) || !exactMembers(headerBytes, []string{"alg", "kid", "typ"}) ||
		header.Algorithm != "EdDSA" || header.Type != expectedTokenType || !validText(header.KeyID, 1, 128) {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	key, exists := a.keys[header.KeyID]
	if !exists || key.revoked || !ed25519.Verify(key.publicKey, []byte(segments[0]+"."+segments[1]), signature) {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	var claims tokenClaims
	if !decodeClosed(claimsBytes, &claims) || !exactMembers(claimsBytes, requiredClaims[:]) || claims.Issuer != a.issuer ||
		claims.Audience != a.audience || claims.Subject != claims.ActorID || !validText(claims.TenantID, 1, 200) ||
		!validText(claims.JTI, 16, 200) || claims.Actor().Validate() != nil || !validRole(claims.Role) {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	now := a.clock.Now().UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0)
	notBefore := time.Unix(claims.NotBefore, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if claims.IssuedAt < 0 || claims.NotBefore < 0 || claims.ExpiresAt < 0 || expiresAt.Sub(issuedAt) <= 0 ||
		expiresAt.Sub(issuedAt) > a.maxLifetime || notBefore.Before(issuedAt.Add(-a.clockSkew)) ||
		notBefore.After(expiresAt) ||
		issuedAt.After(now.Add(a.clockSkew)) || notBefore.After(now.Add(a.clockSkew)) || !expiresAt.After(now.Add(-a.clockSkew)) ||
		now.Before(key.notBefore.Add(-a.clockSkew)) || !now.Before(key.notAfter.Add(a.clockSkew)) {
		return productapi.Principal{}, productapi.ErrUnauthenticated
	}
	return productapi.Principal{TenantID: claims.TenantID, Actor: product.ActorRef{Type: claims.ActorType, ID: claims.ActorID}, Role: claims.Role}, nil
}

func (c tokenClaims) Actor() product.ActorRef {
	return product.ActorRef{Type: c.ActorType, ID: c.ActorID}
}

func validRole(role productapi.Role) bool {
	return role == productapi.RoleOwner || role == productapi.RoleController || role == productapi.RoleViewer
}

func decodeSegment(value string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && len(decoded) > 0
}

func decodeClosed(raw []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && requireEOF(decoder) == nil
}

func exactMembers(raw []byte, names []string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(names) {
		return false
	}
	for _, name := range names {
		value, exists := object[name]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func validIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" && parsed.String() == value && len(value) <= 2048
}

func validAbsoluteURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && (parsed.Host != "" || parsed.Opaque != "") && parsed.Fragment == "" && parsed.String() == value && len(value) <= 2048
}

func validText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n") && len(value) >= minimum && len(value) <= maximum
}

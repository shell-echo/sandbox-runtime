package admission

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testAdmissionIssuer  = "https://caller.example.invalid/sandbox-runtime"
	testProviderRevision = "provider-revision-1"
	testProviderAudience = "urn:shell-echo:sandbox-runtime:provider-instance:provider-1"
)

func TestVerifyCompactJWSSucceedsForLockedAlgorithms(t *testing.T) {
	for _, fixture := range []signingFixture{newEdDSAFixture(t), newES256Fixture(t)} {
		t.Run(string(fixture.algorithm), func(t *testing.T) {
			token := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, validTokenClaims())
			verified, err := VerifyCompactJWS(context.Background(), token, fixture.keys, validAdmissionAuthorityForTest())
			if err != nil {
				t.Fatalf("VerifyCompactJWS() error = %v", err)
			}
			if verified.Header.Algorithm != fixture.algorithm || verified.Header.KeyID != fixture.keyID || verified.Claims.Operation != OperationExec {
				t.Fatalf("verified token = %#v", verified)
			}
		})
	}
}

func TestVerifyCompactJWSRejectsClosedHeaderAndSignatureFailures(t *testing.T) {
	fixture := newEdDSAFixture(t)
	validHeader := JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}
	tests := []struct {
		name    string
		keys    TrustedKeySource
		header  any
		payload any
		raw     bool
	}{
		{name: "unknown header", keys: fixture.keys, header: map[string]any{"alg": fixture.algorithm, "kid": fixture.keyID, "typ": expectedJWSType, "extra": true}, payload: validTokenClaims()},
		{name: "wrong type", keys: fixture.keys, header: JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: "JWT"}, payload: validTokenClaims()},
		{name: "legacy pre-context type", keys: fixture.keys, header: JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: "agent-sandbox-operation+jwt"}, payload: validTokenClaims()},
		{name: "unsupported algorithm", keys: fixture.keys, header: map[string]any{"alg": "none", "kid": fixture.keyID, "typ": expectedJWSType}, payload: validTokenClaims()},
		{name: "oversized key identifier", keys: fixture.keys, header: JWSHeader{Algorithm: fixture.algorithm, KeyID: KeyID(strings.Repeat("k", 129)), Type: expectedJWSType}, payload: validTokenClaims()},
		{name: "unknown key", keys: keySource{}, header: validHeader, payload: validTokenClaims()},
		{name: "duplicate header", keys: fixture.keys, header: `{"alg":"EdDSA","alg":"EdDSA","kid":"test-ed","typ":"agent-sandbox-operation-admission+jwt"}`, payload: validTokenClaims(), raw: true},
		{name: "case-variant header members", keys: fixture.keys, header: `{"ALG":"EdDSA","KID":"test-ed","TYP":"agent-sandbox-operation-admission+jwt"}`, payload: validTokenClaims(), raw: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var token string
			if test.raw {
				token = fixture.rawToken(t, []byte(test.header.(string)), marshalJSON(t, test.payload))
			} else {
				token = fixture.token(t, test.header, test.payload)
			}
			if _, err := VerifyCompactJWS(context.Background(), token, test.keys, validAdmissionAuthorityForTest()); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("VerifyCompactJWS() error = %v, want ErrInvalidToken", err)
			}
		})
	}

	other := newEdDSAFixture(t)
	token := fixture.token(t, validHeader, validTokenClaims())
	if _, err := VerifyCompactJWS(context.Background(), token, other.keys, validAdmissionAuthorityForTest()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("signature mismatch error = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyCompactJWSRejectsClosedClaimFailures(t *testing.T) {
	fixture := newEdDSAFixture(t)
	header := JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}
	tests := []struct {
		name    string
		payload any
	}{
		{name: "unknown claim", payload: map[string]any{"jti": "jti-1", "iss": testAdmissionIssuer, "sub": "spiffe://provider/controller", "aud": testProviderAudience, "iat": 1, "nbf": 1, "exp": 2, "operation": OperationExec, "provider_revision_id": testProviderRevision, "sandbox_id": "sandbox-1", "operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": 1, "tenant_id": "tenant-1", "work_order_id": "work-order-1", "policy_digest": validDigest('a'), "request_contract_id": "urn:shell-echo:sandbox-runtime:request:exec:v1", "request_digest_profile": DigestProfileRequestExcludingDigest, "request_digest": validDigest('b'), "deadline_at": "2026-08-19T16:00:00Z", "extra": true}},
		{name: "duplicate claim", payload: `{"jti":"jti-1","jti":"jti-2","iss":"https://caller.example.invalid/sandbox-runtime","sub":"spiffe://provider/controller","aud":"urn:shell-echo:sandbox-runtime:provider-instance:provider-1","iat":1,"nbf":1,"exp":2,"operation":"exec","provider_revision_id":"provider-revision-1","sandbox_id":"sandbox-1","operation_id":"operation-1","attempt_id":"attempt-1","fencing_token":1,"tenant_id":"tenant-1","work_order_id":"work-order-1","policy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_contract_id":"urn:shell-echo:sandbox-runtime:request:exec:v1","request_digest_profile":"rfc8785-request-excluding-request-digest-v1","request_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","deadline_at":"2026-08-19T16:00:00Z"}`},
		{name: "unsupported operation", payload: mutateClaims(func(claims *TokenClaims) { claims.Operation = "undeclared" })},
		{name: "missing issued at", payload: tokenClaimsWithout(t, "iat")},
		{name: "null issued at", payload: tokenClaimsWith(t, "iat", nil)},
		{name: "malformed issuer", payload: mutateClaims(func(claims *TokenClaims) { claims.Issuer = "https://caller.example.invalid/#fragment" })},
		{name: "invalid digest", payload: mutateClaims(func(claims *TokenClaims) { claims.RequestDigest = "sha256:invalid" })},
		{name: "invalid deadline", payload: mutateClaims(func(claims *TokenClaims) { claims.DeadlineAt = "tomorrow" })},
		{name: "zero fencing token", payload: mutateClaims(func(claims *TokenClaims) { claims.FencingToken = 0 })},
		{name: "unsafe fencing token", payload: mutateClaims(func(claims *TokenClaims) { claims.FencingToken = maxSafeJSONInteger + 1 })},
		{name: "short jti", payload: mutateClaims(func(claims *TokenClaims) { claims.JTI = "short" })},
		{name: "oversized jti", payload: mutateClaims(func(claims *TokenClaims) { claims.JTI = strings.Repeat("j", 201) })},
		{name: "oversized subject", payload: mutateClaims(func(claims *TokenClaims) { claims.Subject = strings.Repeat("s", 201) })},
		{name: "oversized provider revision", payload: mutateClaims(func(claims *TokenClaims) { claims.ProviderRevisionID = strings.Repeat("r", 201) })},
		{name: "oversized sandbox id", payload: mutateClaims(func(claims *TokenClaims) { claims.SandboxID = strings.Repeat("s", 201) })},
		{name: "oversized operation id", payload: mutateClaims(func(claims *TokenClaims) { claims.OperationID = strings.Repeat("o", 201) })},
		{name: "oversized attempt id", payload: mutateClaims(func(claims *TokenClaims) { claims.AttemptID = strings.Repeat("a", 201) })},
		{name: "oversized tenant id", payload: mutateClaims(func(claims *TokenClaims) { claims.TenantID = strings.Repeat("t", 201) })},
		{name: "oversized work order id", payload: mutateClaims(func(claims *TokenClaims) { claims.WorkOrderID = strings.Repeat("w", 201) })},
		{name: "wrong operation contract", payload: mutateClaims(func(claims *TokenClaims) {
			claims.RequestContractID = "urn:shell-echo:sandbox-runtime:request:create:v1"
		})},
		{name: "wrong digest profile", payload: mutateClaims(func(claims *TokenClaims) { claims.RequestDigestProfile = DigestProfileFullDocument })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var token string
			if raw, ok := test.payload.(string); ok {
				token = fixture.rawToken(t, marshalJSON(t, header), []byte(raw))
			} else {
				token = fixture.token(t, header, test.payload)
			}
			if _, err := VerifyCompactJWS(context.Background(), token, fixture.keys, validAdmissionAuthorityForTest()); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("VerifyCompactJWS() error = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyCompactJWSRejectsTrustedIssuerSubstitution(t *testing.T) {
	fixture := newEdDSAFixture(t)
	claims := validTokenClaims()
	claims.Issuer = "https://other-caller.example.invalid/sandbox-runtime"
	token := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, claims)

	_, err := VerifyCompactJWS(context.Background(), token, fixture.keys, validAdmissionAuthorityForTest())
	if err != ErrInvalidToken {
		t.Fatalf("VerifyCompactJWS() error = %v, want exact ErrInvalidToken", err)
	}
	if strings.Contains(err.Error(), claims.Issuer) {
		t.Fatalf("VerifyCompactJWS() error disclosed substituted issuer: %v", err)
	}
}

func TestVerifyCompactJWSSupportsOverlappingRotationKeys(t *testing.T) {
	current := newEdDSAFixture(t)
	next := newEdDSAFixture(t)
	nextPublicKey := next.keys[next.keyID]
	next.keyID = "test-ed-next"

	keys, err := NewStaticTrustedKeySource([]StaticTrustedKey{
		{ID: current.keyID, Algorithm: current.algorithm, PublicKey: current.keys[current.keyID]},
		{ID: next.keyID, Algorithm: next.algorithm, PublicKey: nextPublicKey},
	})
	if err != nil {
		t.Fatalf("NewStaticTrustedKeySource() error = %v", err)
	}

	for _, fixture := range []signingFixture{current, next} {
		t.Run(string(fixture.keyID), func(t *testing.T) {
			token := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, validTokenClaims())
			if _, err := VerifyCompactJWS(context.Background(), token, keys, validAdmissionAuthorityForTest()); err != nil {
				t.Fatalf("VerifyCompactJWS() error = %v", err)
			}
		})
	}
}

func TestVerifyCompactJWSRequiresEachOperationBinding(t *testing.T) {
	fixture := newEdDSAFixture(t)
	header := JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}
	for operation, binding := range requestBindings {
		t.Run(string(operation), func(t *testing.T) {
			claims := validTokenClaims()
			claims.Operation = operation
			claims.RequestContractID = binding.contractID
			claims.RequestDigestProfile = binding.profile
			token := fixture.token(t, header, claims)
			if _, err := VerifyCompactJWS(context.Background(), token, fixture.keys, validAdmissionAuthorityForTest()); err != nil {
				t.Fatalf("VerifyCompactJWS() error = %v", err)
			}
		})
	}
}

func TestVerifyCompactJWSPreservesCanceledContextAndBoundsInput(t *testing.T) {
	fixture := newEdDSAFixture(t)
	token := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSType}, validTokenClaims())
	if _, err := VerifyCompactJWS(context.Background(), token, fixture.keys, AdmissionAuthority{}); err != ErrInvalidToken {
		t.Fatalf("zero authority error = %v, want exact ErrInvalidToken", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyCompactJWS(ctx, "not.a.token", fixture.keys, validAdmissionAuthorityForTest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want %v", err, context.Canceled)
	}
	if _, err := VerifyCompactJWS(context.Background(), strings.Repeat("a", maxCompactJWSBytes+1), fixture.keys, validAdmissionAuthorityForTest()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("oversized token error = %v, want ErrInvalidToken", err)
	}
}

type signingFixture struct {
	algorithm Algorithm
	keyID     KeyID
	keys      keySource
	sign      func([]byte) []byte
}

func newEdDSAFixture(t *testing.T) signingFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return signingFixture{
		algorithm: AlgorithmEdDSA,
		keyID:     "test-ed",
		keys:      keySource{"test-ed": publicKey},
		sign:      func(input []byte) []byte { return ed25519.Sign(privateKey, input) },
	}
}

func newES256Fixture(t *testing.T) signingFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return signingFixture{
		algorithm: AlgorithmES256,
		keyID:     "test-es",
		keys:      keySource{"test-es": &privateKey.PublicKey},
		sign: func(input []byte) []byte {
			digest := sha256.Sum256(input)
			r, s, signErr := ecdsa.Sign(rand.Reader, privateKey, digest[:])
			if signErr != nil {
				t.Fatalf("sign ES256 input: %v", signErr)
			}
			signature := make([]byte, 64)
			r.FillBytes(signature[:32])
			s.FillBytes(signature[32:])
			return signature
		},
	}
}

func (fixture signingFixture) token(t *testing.T, header, claims any) string {
	t.Helper()
	return fixture.rawToken(t, marshalJSON(t, header), marshalJSON(t, claims))
}

func (fixture signingFixture) rawToken(t *testing.T, header, payload []byte) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(fixture.sign([]byte(signingInput)))
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return encoded
}

type keySource map[KeyID]crypto.PublicKey

func (source keySource) Lookup(ctx context.Context, keyID KeyID, _ Algorithm) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, ok := source[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func validTokenClaims() TokenClaims {
	return TokenClaims{
		JTI:                           "jti-000000000000",
		Issuer:                        testAdmissionIssuer,
		Subject:                       "spiffe://provider/controller",
		Audience:                      testProviderAudience,
		IssuedAt:                      1,
		NotBefore:                     1,
		ExpiresAt:                     2,
		Operation:                     OperationExec,
		ProviderRevisionID:            testProviderRevision,
		SandboxID:                     "sandbox-1",
		OperationID:                   "operation-1",
		AttemptID:                     "attempt-1",
		FencingToken:                  1,
		TenantID:                      "tenant-1",
		WorkOrderID:                   "work-order-1",
		PolicyDigest:                  validDigest('a'),
		PolicyDecidedAt:               time.Unix(105, 0).UTC().Format(time.RFC3339Nano),
		RequestContractID:             "urn:shell-echo:sandbox-runtime:request:exec:v1",
		RequestDigestProfile:          DigestProfileRequestExcludingDigest,
		RequestDigest:                 validDigest('b'),
		DeadlineAt:                    "2026-08-19T16:00:00Z",
		AdmissionContextContractID:    AdmissionContextContractID,
		AdmissionContextDigestProfile: AdmissionContextDigestProfile,
		AdmissionContextDigest:        validDigest('c'),
	}
}

func tokenClaimsWithout(t *testing.T, name string) map[string]any {
	claims := tokenClaimsMap(t)
	delete(claims, name)
	return claims
}

func tokenClaimsWith(t *testing.T, name string, value any) map[string]any {
	claims := tokenClaimsMap(t)
	claims[name] = value
	return claims
}

func tokenClaimsMap(t *testing.T) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(validTokenClaims())
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(encoded, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func validAdmissionAuthorityForTest() AdmissionAuthority {
	authority, err := NewAdmissionAuthority(testAdmissionIssuer, testProviderRevision, testProviderAudience)
	if err != nil {
		panic(err)
	}
	return authority
}

func mutateClaims(mutate func(*TokenClaims)) TokenClaims {
	claims := validTokenClaims()
	mutate(&claims)
	return claims
}

func validDigest(character rune) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}

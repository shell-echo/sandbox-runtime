package admission

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxCompactJWSBytes       = 8 << 10
	expectedJWSType          = "agent-sandbox-operation+jwt"
	expectedJWSAdmissionType = "agent-sandbox-operation-admission+jwt"
	expectedIssuer           = "agent-platform"
)

var (
	ErrInvalidToken = errors.New("provider admission token is invalid")

	audiencePattern = regexp.MustCompile(`^urn:shell-echo:sandbox-runtime:provider-instance:[A-Za-z0-9._:-]{1,200}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Operation is a protected Sandbox Provider operation named by a token claim.
type Operation string

const (
	OperationCreate               Operation = "create"
	OperationRestore              Operation = "restore"
	OperationSetDesiredState      Operation = "set_desired_state"
	OperationExtendLease          Operation = "extend_lease"
	OperationExec                 Operation = "exec"
	OperationCancelExec           Operation = "cancel_exec"
	OperationOpenRuntimeSession   Operation = "open_runtime_session"
	OperationSnapshot             Operation = "snapshot"
	OperationTerminate            Operation = "terminate"
	OperationReadSandbox          Operation = "read_sandbox"
	OperationReadOperation        Operation = "read_operation"
	OperationReadResult           Operation = "read_result"
	OperationReadSnapshotManifest Operation = "read_snapshot_manifest"
	OperationReadEvents           Operation = "read_events"
)

// Supported reports whether operation is in the closed token claim allowlist.
func (operation Operation) Supported() bool {
	switch operation {
	case OperationCreate, OperationRestore, OperationSetDesiredState,
		OperationExtendLease, OperationExec, OperationCancelExec,
		OperationOpenRuntimeSession, OperationSnapshot, OperationTerminate,
		OperationReadSandbox, OperationReadOperation, OperationReadResult,
		OperationReadSnapshotManifest, OperationReadEvents:
		return true
	default:
		return false
	}
}

// DigestProfile identifies the canonical representation bound by a token.
type DigestProfile string

const (
	DigestProfileRequestExcludingDigest DigestProfile = "rfc8785-request-excluding-request-digest-v1"
	DigestProfileFullDocument           DigestProfile = "rfc8785-full-document-v1"
)

// Supported reports whether profile is in the closed token claim allowlist.
func (profile DigestProfile) Supported() bool {
	return profile == DigestProfileRequestExcludingDigest || profile == DigestProfileFullDocument
}

// JWSHeader is the closed protected-operation JWS header.
type JWSHeader struct {
	Algorithm Algorithm `json:"alg"`
	KeyID     KeyID     `json:"kid"`
	Type      string    `json:"typ"`
}

// TokenClaims is the locked protected-operation claims surface. It represents
// a verified closed claim shape and its operation-specific Contract binding.
// Contextual caller, request, temporal, replay, and fencing checks remain
// separate P1.1c admission units.
type TokenClaims struct {
	JTI                           string        `json:"jti"`
	Issuer                        string        `json:"iss"`
	Subject                       string        `json:"sub"`
	Audience                      string        `json:"aud"`
	IssuedAt                      int64         `json:"iat"`
	NotBefore                     int64         `json:"nbf"`
	ExpiresAt                     int64         `json:"exp"`
	Operation                     Operation     `json:"operation"`
	ProviderRevisionID            string        `json:"provider_revision_id"`
	SandboxID                     string        `json:"sandbox_id"`
	OperationID                   string        `json:"operation_id"`
	AttemptID                     string        `json:"attempt_id"`
	FencingToken                  int64         `json:"fencing_token"`
	TenantID                      string        `json:"tenant_id"`
	WorkOrderID                   string        `json:"work_order_id"`
	PolicyDigest                  string        `json:"policy_digest"`
	PolicyDecidedAt               string        `json:"policy_decided_at"`
	RequestContractID             string        `json:"request_contract_id"`
	RequestDigestProfile          DigestProfile `json:"request_digest_profile"`
	RequestDigest                 string        `json:"request_digest"`
	DeadlineAt                    string        `json:"deadline_at"`
	AdmissionContextContractID    string        `json:"admission_context_contract_id"`
	AdmissionContextDigestProfile string        `json:"admission_context_digest_profile"`
	AdmissionContextDigest        string        `json:"admission_context_digest"`
}

// VerifiedToken contains a signature-verified, closed header and claims shape.
// It intentionally retains neither the compact bearer value nor its signature.
type VerifiedToken struct {
	Header JWSHeader
	Claims TokenClaims
}

// VerifyCompactJWS verifies a bounded compact JWS against keys and rejects a
// header or claims document outside the locked closed surface. Contextual
// caller, request, temporal, replay, and fencing binding are separate steps.
func VerifyCompactJWS(ctx context.Context, compact string, keys TrustedKeySource) (VerifiedToken, error) {
	if ctx == nil {
		return VerifiedToken{}, ErrInvalidToken
	}
	if err := ctx.Err(); err != nil {
		return VerifiedToken{}, err
	}
	if keys == nil || len(compact) == 0 || len(compact) > maxCompactJWSBytes {
		return VerifiedToken{}, ErrInvalidToken
	}

	segments := strings.Split(compact, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return VerifiedToken{}, ErrInvalidToken
	}
	headerBytes, ok := decodeCompactSegment(segments[0])
	if !ok {
		return VerifiedToken{}, ErrInvalidToken
	}
	payloadBytes, ok := decodeCompactSegment(segments[1])
	if !ok {
		return VerifiedToken{}, ErrInvalidToken
	}
	signature, ok := decodeCompactSegment(segments[2])
	if !ok {
		return VerifiedToken{}, ErrInvalidToken
	}

	var header JWSHeader
	if !decodeClosedJSON(headerBytes, &header) || !validateHeader(header) {
		return VerifiedToken{}, ErrInvalidToken
	}
	var claims TokenClaims
	if !decodeClosedJSON(payloadBytes, &claims) || !validateClaimsForHeader(header, claims) {
		return VerifiedToken{}, ErrInvalidToken
	}

	key, err := keys.Lookup(ctx, header.KeyID, header.Algorithm)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return VerifiedToken{}, contextErr
		}
		return VerifiedToken{}, ErrInvalidToken
	}
	if !verifySignature(header.Algorithm, key, []byte(segments[0]+"."+segments[1]), signature) {
		return VerifiedToken{}, ErrInvalidToken
	}
	return VerifiedToken{Header: header, Claims: claims}, nil
}

func decodeCompactSegment(segment string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

func validateHeader(header JWSHeader) bool {
	return header.Algorithm.Supported() && (header.Type == expectedJWSType || header.Type == expectedJWSAdmissionType) && validBoundedText(string(header.KeyID), 1, 200)
}

func validateClaimsForHeader(header JWSHeader, claims TokenClaims) bool {
	if !validateClaimsShape(claims) {
		return false
	}
	if header.Type != expectedJWSAdmissionType {
		return claims.AdmissionContextContractID == "" && claims.AdmissionContextDigestProfile == "" && claims.AdmissionContextDigest == ""
	}
	if claims.PolicyDecidedAt == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, claims.PolicyDecidedAt); err != nil {
		return false
	}
	return claims.AdmissionContextContractID == AdmissionContextContractID && claims.AdmissionContextDigestProfile == AdmissionContextDigestProfile && digestPattern.MatchString(claims.AdmissionContextDigest)
}

func validateClaimsShape(claims TokenClaims) bool {
	if claims.Issuer != expectedIssuer || !claims.Operation.Supported() || !claims.RequestDigestProfile.Supported() || !validRequestBinding(claims) {
		return false
	}
	if claims.IssuedAt < 0 || claims.NotBefore < 0 || claims.ExpiresAt < 0 || claims.FencingToken < 1 {
		return false
	}
	if !audiencePattern.MatchString(claims.Audience) || !digestPattern.MatchString(claims.PolicyDigest) || !digestPattern.MatchString(claims.RequestDigest) {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, claims.DeadlineAt); err != nil {
		return false
	}
	if claims.PolicyDecidedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, claims.PolicyDecidedAt); err != nil {
			return false
		}
	}
	if !validBoundedText(claims.JTI, 16, 200) || !validBoundedText(claims.Subject, 1, 200) {
		return false
	}
	for _, value := range []string{
		claims.ProviderRevisionID, claims.SandboxID,
		claims.OperationID, claims.AttemptID, claims.TenantID, claims.WorkOrderID,
	} {
		if !validRequiredText(value) {
			return false
		}
	}
	return true
}

type requestBinding struct {
	contractID string
	profile    DigestProfile
}

var requestBindings = map[Operation]requestBinding{
	OperationCreate:               {contractID: "urn:shell-echo:sandbox-runtime:request:create:v1", profile: DigestProfileRequestExcludingDigest},
	OperationRestore:              {contractID: "urn:shell-echo:sandbox-runtime:request:restore:v1", profile: DigestProfileRequestExcludingDigest},
	OperationSetDesiredState:      {contractID: "urn:shell-echo:sandbox-runtime:request:set-desired-state:v1", profile: DigestProfileRequestExcludingDigest},
	OperationExtendLease:          {contractID: "urn:shell-echo:sandbox-runtime:request:extend-lease:v1", profile: DigestProfileRequestExcludingDigest},
	OperationExec:                 {contractID: "urn:shell-echo:sandbox-runtime:request:exec:v1", profile: DigestProfileRequestExcludingDigest},
	OperationCancelExec:           {contractID: "urn:shell-echo:sandbox-runtime:request:cancel-exec:v1", profile: DigestProfileRequestExcludingDigest},
	OperationOpenRuntimeSession:   {contractID: "urn:shell-echo:sandbox-runtime:request:open-runtime-session:v1", profile: DigestProfileRequestExcludingDigest},
	OperationSnapshot:             {contractID: "urn:shell-echo:sandbox-runtime:request:snapshot:v1", profile: DigestProfileRequestExcludingDigest},
	OperationTerminate:            {contractID: "urn:shell-echo:sandbox-runtime:request:terminate:v1", profile: DigestProfileRequestExcludingDigest},
	OperationReadSandbox:          {contractID: "urn:shell-echo:sandbox-runtime:descriptor:status:v1", profile: DigestProfileFullDocument},
	OperationReadOperation:        {contractID: "urn:shell-echo:sandbox-runtime:descriptor:operation:v1", profile: DigestProfileFullDocument},
	OperationReadResult:           {contractID: "urn:shell-echo:sandbox-runtime:descriptor:exec-result:v1", profile: DigestProfileFullDocument},
	OperationReadSnapshotManifest: {contractID: "urn:shell-echo:sandbox-runtime:descriptor:snapshot-manifest:v1", profile: DigestProfileFullDocument},
	OperationReadEvents:           {contractID: "urn:shell-echo:sandbox-runtime:descriptor:events:v1", profile: DigestProfileFullDocument},
}

func validRequestBinding(claims TokenClaims) bool {
	binding, ok := requestBindings[claims.Operation]
	return ok && claims.RequestContractID == binding.contractID && claims.RequestDigestProfile == binding.profile
}

func validRequiredText(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != ""
}

func validBoundedText(value string, minimum, maximum int) bool {
	if !validRequiredText(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func verifySignature(algorithm Algorithm, key crypto.PublicKey, signingInput, signature []byte) bool {
	switch algorithm {
	case AlgorithmEdDSA:
		publicKey, ok := key.(ed25519.PublicKey)
		return ok && len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, signingInput, signature)
	case AlgorithmES256:
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok || publicKey == nil || publicKey.Curve == nil || publicKey.Curve.Params() == nil || publicKey.Curve.Params().Name != elliptic.P256().Params().Name || len(signature) != 64 {
			return false
		}
		digest := sha256.Sum256(signingInput)
		return ecdsa.Verify(publicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	default:
		return false
	}
}

func decodeClosedJSON(data []byte, destination any) bool {
	if !hasNoDuplicateJSONKeys(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func hasNoDuplicateJSONKeys(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder); err != nil {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := keys[key]; exists {
					return errors.New("duplicate JSON object key")
				}
				keys[key] = struct{}{}
				if valueErr := consumeJSONValue(decoder); valueErr != nil {
					return valueErr
				}
			}
			closing, closingErr := decoder.Token()
			if closingErr != nil || closing != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if valueErr := consumeJSONValue(decoder); valueErr != nil {
					return valueErr
				}
			}
			closing, closingErr := decoder.Token()
			if closingErr != nil || closing != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return nil
}

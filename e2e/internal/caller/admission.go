package caller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	admissionContextHeader        = "X-Sandbox-Runtime-Admission-Context"
	admissionContextContractID    = "urn:shell-echo:sandbox-runtime:admission-context:v1"
	admissionContextDigestProfile = "rfc8785-full-document-excluding-context-digest-v1"
	requestDigestExcluding        = "rfc8785-request-excluding-request-digest-v1"
	requestDigestFull             = "rfc8785-full-document-v1"
	jwsType                       = "agent-sandbox-operation-admission+jwt"
	jwsIssuer                     = "agent-platform"
)

var operationContracts = map[string]struct {
	contractID string
	profile    string
	mutation   bool
}{
	"create":                         {"urn:shell-echo:sandbox-runtime:request:create:v1", requestDigestExcluding, true},
	"exec":                           {"urn:shell-echo:sandbox-runtime:request:exec:v1", requestDigestExcluding, true},
	"cancel_exec":                    {"urn:shell-echo:sandbox-runtime:request:cancel-exec:v1", requestDigestExcluding, true},
	"open_runtime_session":           {"urn:shell-echo:sandbox-runtime:request:open-runtime-session:v1", requestDigestExcluding, true},
	"stage_artifact":                 {"urn:shell-echo:sandbox-runtime:request:stage-artifact:v1", requestDigestExcluding, true},
	"read_sandbox":                   {"urn:shell-echo:sandbox-runtime:descriptor:status:v1", requestDigestFull, false},
	"read_operation":                 {"urn:shell-echo:sandbox-runtime:descriptor:operation:v1", requestDigestFull, false},
	"read_result":                    {"urn:shell-echo:sandbox-runtime:descriptor:exec-result:v1", requestDigestFull, false},
	"read_runtime_session":           {"urn:shell-echo:sandbox-runtime:descriptor:runtime-session:v1", requestDigestFull, false},
	"read_artifact_staging_evidence": {"urn:shell-echo:sandbox-runtime:descriptor:artifact-staging-evidence:v1", requestDigestFull, false},
	"read_usage_evidence":            {"urn:shell-echo:sandbox-runtime:descriptor:usage-evidence:v1", requestDigestFull, false},
}

type signer struct {
	identity IdentityConfig
	private  ed25519.PrivateKey
}

type admissionBinding struct {
	Operation    string
	SandboxID    string
	OperationID  string
	AttemptID    string
	FencingToken int64
	TenantID     string
	WorkOrderID  string
	Deadline     time.Time
	JTI          string
}

type preparedRequest struct {
	Method           string
	Path             string
	Body             []byte
	Authorization    string
	AdmissionContext string
}

type admissionContext struct {
	ContextContractID        string          `json:"context_contract_id"`
	ContextDigestProfile     string          `json:"context_digest_profile"`
	ContextDigest            string          `json:"context_digest"`
	ControllerSubject        string          `json:"controller_subject"`
	ProviderRevisionID       string          `json:"provider_revision_id"`
	ProviderInstanceAudience string          `json:"provider_instance_audience"`
	TenantID                 string          `json:"tenant_id"`
	WorkOrderID              string          `json:"work_order_id"`
	PolicyDigest             string          `json:"policy_digest"`
	PolicyDecidedAt          string          `json:"policy_decided_at"`
	Operation                string          `json:"operation"`
	SandboxID                string          `json:"sandbox_id"`
	OperationID              string          `json:"operation_id"`
	AttemptID                string          `json:"attempt_id"`
	FencingToken             int64           `json:"fencing_token"`
	DeadlineAt               string          `json:"deadline_at"`
	RequestContractID        string          `json:"request_contract_id"`
	RequestDigestProfile     string          `json:"request_digest_profile"`
	RequestDigest            string          `json:"request_digest"`
	HTTPTarget               admissionTarget `json:"http_target"`
}

type admissionTarget struct {
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	NormalizedQuery []admissionQuery `json:"normalized_query"`
}

type admissionQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type jwsHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type tokenClaims struct {
	JTI                           string `json:"jti"`
	Issuer                        string `json:"iss"`
	Subject                       string `json:"sub"`
	Audience                      string `json:"aud"`
	IssuedAt                      int64  `json:"iat"`
	NotBefore                     int64  `json:"nbf"`
	ExpiresAt                     int64  `json:"exp"`
	Operation                     string `json:"operation"`
	ProviderRevisionID            string `json:"provider_revision_id"`
	SandboxID                     string `json:"sandbox_id"`
	OperationID                   string `json:"operation_id"`
	AttemptID                     string `json:"attempt_id"`
	FencingToken                  int64  `json:"fencing_token"`
	TenantID                      string `json:"tenant_id"`
	WorkOrderID                   string `json:"work_order_id"`
	PolicyDigest                  string `json:"policy_digest"`
	PolicyDecidedAt               string `json:"policy_decided_at"`
	RequestContractID             string `json:"request_contract_id"`
	RequestDigestProfile          string `json:"request_digest_profile"`
	RequestDigest                 string `json:"request_digest"`
	DeadlineAt                    string `json:"deadline_at"`
	AdmissionContextContractID    string `json:"admission_context_contract_id"`
	AdmissionContextDigestProfile string `json:"admission_context_digest_profile"`
	AdmissionContextDigest        string `json:"admission_context_digest"`
}

func loadSigner(identity IdentityConfig) (*signer, error) {
	content, err := os.ReadFile(identity.JWSPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read JWS private key: %w", err)
	}
	block, trailing := pem.Decode(content)
	if block == nil || len(trailing) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("JWS private key is not one PKCS8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse JWS private key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("JWS private key is not Ed25519")
	}
	return &signer{identity: identity, private: private}, nil
}

func (s *signer) prepare(config Config, method, path string, body map[string]any, binding admissionBinding) (preparedRequest, error) {
	operation, ok := operationContracts[binding.Operation]
	if !ok {
		return preparedRequest{}, fmt.Errorf("unsupported operation %q", binding.Operation)
	}
	if binding.Deadline.IsZero() || !binding.Deadline.After(time.Now().UTC()) || binding.FencingToken < 1 {
		return preparedRequest{}, errors.New("invalid admission binding")
	}
	var document []byte
	var err error
	if operation.mutation {
		if body == nil {
			return preparedRequest{}, errors.New("mutation body is required")
		}
		delete(body, "request_digest")
		digest, digestErr := canonicalDigest(body)
		if digestErr != nil {
			return preparedRequest{}, digestErr
		}
		body["request_digest"] = digest
		document, err = json.Marshal(body)
	} else {
		if body != nil {
			return preparedRequest{}, errors.New("read body must be nil")
		}
		descriptor := map[string]any{
			"operation": binding.Operation, "sandbox_id": binding.SandboxID,
			"operation_id": binding.OperationID, "attempt_id": binding.AttemptID,
			"fencing_token": binding.FencingToken,
		}
		document, err = json.Marshal(descriptor)
	}
	if err != nil {
		return preparedRequest{}, err
	}
	requestDigest, err := digestDocument(operation.profile, document)
	if err != nil {
		return preparedRequest{}, err
	}
	policyTime := time.Now().UTC().Truncate(time.Second)
	deadline := binding.Deadline.UTC()
	policyDigest := sha256Digest([]byte("sandbox-runtime-e2e-reference-policy-v1"))
	admitted := admissionContext{
		ContextContractID: admissionContextContractID, ContextDigestProfile: admissionContextDigestProfile,
		ControllerSubject: s.identity.ControllerSubject, ProviderRevisionID: config.ProviderRevisionID,
		ProviderInstanceAudience: config.ProviderInstanceAudience, TenantID: binding.TenantID, WorkOrderID: binding.WorkOrderID,
		PolicyDigest: policyDigest, PolicyDecidedAt: policyTime.Format(time.RFC3339Nano), Operation: binding.Operation,
		SandboxID: binding.SandboxID, OperationID: binding.OperationID, AttemptID: binding.AttemptID,
		FencingToken: binding.FencingToken, DeadlineAt: deadline.Format(time.RFC3339Nano),
		RequestContractID: operation.contractID, RequestDigestProfile: operation.profile, RequestDigest: requestDigest,
		HTTPTarget: admissionTarget{Method: method, Path: path, NormalizedQuery: []admissionQuery{}},
	}
	contextDigest, err := contextDigest(admitted)
	if err != nil {
		return preparedRequest{}, err
	}
	admitted.ContextDigest = contextDigest
	contextJSON, err := json.Marshal(admitted)
	if err != nil {
		return preparedRequest{}, err
	}
	jti := binding.JTI
	if jti == "" {
		jti, err = randomJTI()
		if err != nil {
			return preparedRequest{}, err
		}
	}
	issuedAt := policyTime.Unix()
	expiresAt := policyTime.Add(time.Minute)
	if expiresAt.After(deadline) {
		expiresAt = deadline
	}
	claims := tokenClaims{
		JTI: jti, Issuer: jwsIssuer, Subject: s.identity.ControllerSubject, Audience: config.ProviderInstanceAudience,
		IssuedAt: issuedAt, NotBefore: issuedAt, ExpiresAt: expiresAt.Unix(), Operation: binding.Operation,
		ProviderRevisionID: config.ProviderRevisionID, SandboxID: binding.SandboxID, OperationID: binding.OperationID,
		AttemptID: binding.AttemptID, FencingToken: binding.FencingToken, TenantID: binding.TenantID,
		WorkOrderID: binding.WorkOrderID, PolicyDigest: policyDigest, PolicyDecidedAt: policyTime.Format(time.RFC3339Nano),
		RequestContractID: operation.contractID, RequestDigestProfile: operation.profile, RequestDigest: requestDigest,
		DeadlineAt: deadline.Format(time.RFC3339Nano), AdmissionContextContractID: admissionContextContractID,
		AdmissionContextDigestProfile: admissionContextDigestProfile, AdmissionContextDigest: contextDigest,
	}
	compact, err := s.sign(claims)
	if err != nil {
		return preparedRequest{}, err
	}
	requestBody := document
	if !operation.mutation {
		requestBody = nil
	}
	return preparedRequest{
		Method: method, Path: path, Body: requestBody, Authorization: "Bearer " + compact,
		AdmissionContext: base64.RawURLEncoding.EncodeToString(contextJSON),
	}, nil
}

func (s *signer) sign(claims tokenClaims) (string, error) {
	header, err := json.Marshal(jwsHeader{Algorithm: "EdDSA", KeyID: s.identity.JWSKeyID, Type: jwsType})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(s.private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func contextDigest(context admissionContext) (string, error) {
	encoded, err := json.Marshal(context)
	if err != nil {
		return "", err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return "", err
	}
	delete(document, "context_digest")
	return canonicalDigest(document)
}

func digestDocument(profile string, document []byte) (string, error) {
	if profile == requestDigestFull {
		canonical, err := jcs.Transform(document)
		if err != nil {
			return "", err
		}
		return sha256Digest(canonical), nil
	}
	if profile != requestDigestExcluding {
		return "", errors.New("unsupported request digest profile")
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(document, &value); err != nil {
		return "", err
	}
	delete(value, "request_digest")
	return canonicalDigest(value)
}

func canonicalDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", err
	}
	return sha256Digest(canonical), nil
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func randomJTI() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "e2e-jti-" + hex.EncodeToString(value[:]), nil
}

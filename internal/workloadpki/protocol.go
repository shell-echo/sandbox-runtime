// Package workloadpki implements the closed repository-private protocol used
// by role-owned agents to obtain short-lived certificates from the independent
// certificate controller. It carries CSRs and public certificates only; TLS
// private keys never cross this boundary.
package workloadpki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const (
	ProtocolID               = "sandbox-runtime.workload-certificate.v1"
	PostgresClientProtocolID = "sandbox-runtime.postgres-client-certificate.v1"

	IssueType       = "issue"
	RevocationsType = "revocations"
	RevokeType      = "revoke"

	CertificateType        = "certificate"
	RevocationSnapshotType = "revocation_snapshot"
	RevokedType            = "revoked"
	ErrorType              = "error"

	StatusOK          = "ok"
	StatusUnavailable = "unavailable"
	StatusDenied      = "denied"

	maxRequestBytes  = 48 << 10
	maxResponseBytes = 512 << 10
	maxCSRBytes      = 16 << 10
	maxPEMBytes      = 64 << 10
	maxCRLBytes      = 256 << 10
)

var (
	ErrInvalid      = errors.New("invalid workload certificate protocol document")
	ErrUnavailable  = errors.New("workload certificate authority unavailable")
	ErrDenied       = errors.New("workload certificate request denied")
	namePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	revisionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	serialPattern   = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){7,31}$`)
	dnsPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type Policy struct {
	ID            string
	Registry      *securityprincipal.Registry
	Requester     securityprincipal.Principal
	Subject       securityprincipal.Principal
	TrustDomain   string
	URI           string
	DNSNames      []string
	Usages        []string
	VaultRole     string
	MaxTTLSeconds int64
	ExpectedUID   uint32
	ExpectedGID   uint32
	PublicKey     ed25519.PublicKey
	Purpose       string
	Postgres      PostgresClientIdentity
}

type Request struct {
	Protocol            string `json:"protocol"`
	Type                string `json:"type"`
	RequestID           string `json:"request_id"`
	AgentID             string `json:"agent_id"`
	RequesterDigest     string `json:"requester_digest"`
	PolicyID            string `json:"policy_id"`
	Principal           string `json:"principal"`
	SubjectDigest       string `json:"subject_digest"`
	Nonce               string `json:"nonce"`
	Deadline            string `json:"deadline"`
	RequestedTTLSeconds int64  `json:"requested_ttl_seconds"`
	CSRPEM              []byte `json:"csr_pem"`
	Serial              string `json:"serial"`
	RequestDigest       string `json:"request_digest"`
	Signature           string `json:"signature"`
}

type Response struct {
	Protocol        string `json:"protocol"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	RequestID       string `json:"request_id"`
	RequestDigest   string `json:"request_digest"`
	AgentID         string `json:"agent_id"`
	PolicyID        string `json:"policy_id"`
	IssuerRevision  string `json:"issuer_revision"`
	CertificatePEM  []byte `json:"certificate_pem"`
	IssuingCAPEM    []byte `json:"issuing_ca_pem"`
	CAChainPEM      []byte `json:"ca_chain_pem"`
	Serial          string `json:"serial"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	CRLDER          []byte `json:"crl_der"`
	CRLThisUpdate   string `json:"crl_this_update"`
	CRLNextUpdate   string `json:"crl_next_update"`
	Revoked         bool   `json:"revoked"`
	ControllerKeyID string `json:"controller_key_id"`
	ResponseDigest  string `json:"response_digest"`
	Signature       string `json:"signature"`
}

func (p Policy) Validate() error {
	parsed, err := url.Parse(p.URI)
	if !namePattern.MatchString(p.ID) || p.Registry == nil || p.Registry.Validate(p.Requester) != nil || p.Registry.Validate(p.Subject) != nil ||
		!validPrincipalDelegation(p.Requester, p.Subject) ||
		!namePattern.MatchString(p.VaultRole) || !validDNS(p.TrustDomain) || err != nil || parsed.Scheme != "spiffe" ||
		parsed.Host != p.TrustDomain || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		len(p.PublicKey) != ed25519.PublicKeySize || p.MaxTTLSeconds < 60 || p.MaxTTLSeconds > 3600 ||
		len(p.DNSNames) > 8 || !sortedUnique(p.DNSNames, validDNS) || !validUsages(p.Usages) {
		return ErrInvalid
	}
	switch p.Purpose {
	case "":
		if p.Postgres != (PostgresClientIdentity{}) {
			return ErrInvalid
		}
	case PostgresClientPurpose:
		if p.Postgres.Validate() != nil || p.URI != p.Postgres.URI ||
			len(p.DNSNames) != 0 || !slices.Equal(p.Usages, []string{"client_auth"}) ||
			p.Postgres.MaxTTL != time.Duration(p.MaxTTLSeconds)*time.Second ||
			p.Subject.Role != securityprincipal.RoleProvider || p.Requester.Role != securityprincipal.RoleProvider {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func protocolForPolicy(policy Policy) string {
	if policy.Purpose == PostgresClientPurpose {
		return PostgresClientProtocolID
	}
	return ProtocolID
}

func NewIssueRequest(policy Policy, requestID, nonce string, deadline time.Time, ttl time.Duration, csrPEM []byte, privateKey ed25519.PrivateKey) (Request, error) {
	request := newRequest(policy, IssueType, requestID, nonce, deadline)
	request.RequestedTTLSeconds = int64(ttl / time.Second)
	request.CSRPEM = append([]byte(nil), csrPEM...)
	return sealRequest(request, policy, privateKey, time.Now().UTC())
}

func NewRevocationsRequest(policy Policy, requestID, nonce string, deadline time.Time, privateKey ed25519.PrivateKey) (Request, error) {
	return sealRequest(newRequest(policy, RevocationsType, requestID, nonce, deadline), policy, privateKey, time.Now().UTC())
}

func NewRevokeRequest(policy Policy, requestID, nonce string, deadline time.Time, serial string, privateKey ed25519.PrivateKey) (Request, error) {
	request := newRequest(policy, RevokeType, requestID, nonce, deadline)
	request.Serial = serial
	return sealRequest(request, policy, privateKey, time.Now().UTC())
}

func newRequest(policy Policy, kind, requestID, nonce string, deadline time.Time) Request {
	return Request{Protocol: protocolForPolicy(policy), Type: kind, RequestID: requestID, AgentID: policy.Requester.Name, RequesterDigest: policy.Requester.Digest(),
		PolicyID: policy.ID, Principal: policy.Subject.Name, SubjectDigest: policy.Subject.Digest(), Nonce: nonce, Deadline: deadline.UTC().Format(time.RFC3339Nano)}
}

func sealRequest(request Request, policy Policy, privateKey ed25519.PrivateKey, now time.Time) (Request, error) {
	if len(privateKey) != ed25519.PrivateKeySize || policy.Validate() != nil || !privateKey.Public().(ed25519.PublicKey).Equal(policy.PublicKey) {
		return Request{}, ErrInvalid
	}
	request.RequestDigest = requestDigest(request)
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(request.RequestDigest)))
	if request.Validate(policy, now) != nil {
		clear(request.CSRPEM)
		return Request{}, ErrInvalid
	}
	return request, nil
}

func (r Request) Validate(policy Policy, now time.Time) error {
	deadline, err := parseTime(r.Deadline)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(r.Signature)
	if policy.Validate() != nil || r.Protocol != protocolForPolicy(policy) || r.AgentID != policy.Requester.Name || r.RequesterDigest != policy.Requester.Digest() ||
		r.PolicyID != policy.ID || r.Principal != policy.Subject.Name || r.SubjectDigest != policy.Subject.Digest() ||
		!namePattern.MatchString(r.RequestID) || !validNonce(r.Nonce) || err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(time.Minute)) ||
		r.RequestDigest != requestDigest(r) || signatureErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(policy.PublicKey, []byte(r.RequestDigest), signature) {
		return ErrDenied
	}
	switch r.Type {
	case IssueType:
		if r.RequestedTTLSeconds < 60 || r.RequestedTTLSeconds > policy.MaxTTLSeconds || len(r.CSRPEM) < 1 || len(r.CSRPEM) > maxCSRBytes || r.Serial != "" || validateCSR(r.CSRPEM, policy) != nil {
			return ErrDenied
		}
	case RevocationsType:
		if r.RequestedTTLSeconds != 0 || len(r.CSRPEM) != 0 || r.Serial != "" {
			return ErrDenied
		}
	case RevokeType:
		if r.RequestedTTLSeconds != 0 || len(r.CSRPEM) != 0 || !serialPattern.MatchString(r.Serial) {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

func NewResponse(request Request, response Response, controllerKeyID string, privateKey ed25519.PrivateKey) (Response, error) {
	if !namePattern.MatchString(controllerKeyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Response{}, ErrInvalid
	}
	response.Protocol, response.RequestID, response.RequestDigest = request.Protocol, request.RequestID, request.RequestDigest
	response.AgentID, response.PolicyID, response.ControllerKeyID = request.AgentID, request.PolicyID, controllerKeyID
	response.ResponseDigest = responseDigest(response)
	response.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(response.ResponseDigest)))
	if response.validateStructure(request) != nil {
		response.Destroy()
		return Response{}, ErrInvalid
	}
	return response, nil
}

func (r Response) Validate(request Request, policy Policy, controllerKeyID string, publicKey ed25519.PublicKey, now time.Time) error {
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if policy.Validate() != nil || request.Validate(policy, now) != nil || len(publicKey) != ed25519.PublicKeySize || r.ControllerKeyID != controllerKeyID || !namePattern.MatchString(controllerKeyID) ||
		r.Protocol != request.Protocol || r.RequestID != request.RequestID || r.RequestDigest != request.RequestDigest || r.AgentID != request.AgentID || r.PolicyID != request.PolicyID ||
		r.ResponseDigest != responseDigest(r) || err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(r.ResponseDigest), signature) ||
		r.validateStructure(request) != nil {
		return ErrUnavailable
	}
	if r.Status != StatusOK {
		if r.Status == StatusDenied {
			return ErrDenied
		}
		return ErrUnavailable
	}
	switch r.Type {
	case CertificateType:
		if validateIssuedCertificate(r, request, policy, now) != nil {
			return ErrUnavailable
		}
	case RevocationSnapshotType:
		if validateRevocationSnapshot(r, now) != nil {
			return ErrUnavailable
		}
	case RevokedType:
		if !r.Revoked || r.Serial != request.Serial {
			return ErrUnavailable
		}
	}
	return nil
}

func (r Response) validateStructure(request Request) error {
	if !revisionPattern.MatchString(r.IssuerRevision) && r.Status == StatusOK || !digestPattern.MatchString(r.ResponseDigest) || !validSignature(r.Signature) {
		return ErrInvalid
	}
	if r.Status != StatusOK {
		if r.Type != ErrorType || (r.Status != StatusUnavailable && r.Status != StatusDenied) || r.IssuerRevision != "" || len(r.CertificatePEM) != 0 || len(r.IssuingCAPEM) != 0 || len(r.CAChainPEM) != 0 || r.Serial != "" || r.NotBefore != "" || r.NotAfter != "" || len(r.CRLDER) != 0 || r.CRLThisUpdate != "" || r.CRLNextUpdate != "" || r.Revoked {
			return ErrInvalid
		}
		return nil
	}
	switch request.Type {
	case IssueType:
		if r.Type != CertificateType || len(r.CertificatePEM) < 1 || len(r.CertificatePEM) > maxPEMBytes || len(r.IssuingCAPEM) < 1 || len(r.IssuingCAPEM) > maxPEMBytes || len(r.CAChainPEM) < 1 || len(r.CAChainPEM) > maxPEMBytes || !serialPattern.MatchString(r.Serial) || r.NotBefore == "" || r.NotAfter == "" || len(r.CRLDER) != 0 || r.CRLThisUpdate != "" || r.CRLNextUpdate != "" || r.Revoked {
			return ErrInvalid
		}
	case RevocationsType:
		if r.Type != RevocationSnapshotType || len(r.CRLDER) < 1 || len(r.CRLDER) > maxCRLBytes || r.CRLThisUpdate == "" || r.CRLNextUpdate == "" || len(r.CertificatePEM) != 0 || len(r.IssuingCAPEM) != 0 || len(r.CAChainPEM) != 0 || r.Serial != "" || r.NotBefore != "" || r.NotAfter != "" || r.Revoked {
			return ErrInvalid
		}
	case RevokeType:
		if r.Type != RevokedType || !r.Revoked || r.Serial != request.Serial || len(r.CertificatePEM) != 0 || len(r.IssuingCAPEM) != 0 || len(r.CAChainPEM) != 0 || r.NotBefore != "" || r.NotAfter != "" || len(r.CRLDER) != 0 || r.CRLThisUpdate != "" || r.CRLNextUpdate != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (r *Response) Destroy() {
	if r == nil {
		return
	}
	clear(r.CertificatePEM)
	clear(r.IssuingCAPEM)
	clear(r.CAChainPEM)
	clear(r.CRLDER)
	r.CertificatePEM, r.IssuingCAPEM, r.CAChainPEM, r.CRLDER = nil, nil, nil, nil
}

func EncodeRequest(request Request, policy Policy, now time.Time) ([]byte, error) {
	if request.Validate(policy, now) != nil {
		return nil, ErrInvalid
	}
	document, err := json.Marshal(request)
	if err != nil || len(document) > maxRequestBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func DecodeRequest(document []byte, policies map[string]Policy, now time.Time) (Request, Policy, error) {
	var request Request
	if decodeCanonical(document, maxRequestBytes, &request) != nil {
		return Request{}, Policy{}, ErrInvalid
	}
	policy, ok := policies[request.PolicyID]
	if !ok || request.Validate(policy, now) != nil {
		clear(request.CSRPEM)
		return Request{}, Policy{}, ErrDenied
	}
	return request, policy, nil
}

func EncodeResponse(response Response, request Request) ([]byte, error) {
	if response.validateStructure(request) != nil {
		return nil, ErrInvalid
	}
	document, err := json.Marshal(response)
	if err != nil || len(document) > maxResponseBytes {
		return nil, ErrInvalid
	}
	return document, nil
}

func DecodeResponse(document []byte, request Request, policy Policy, controllerKeyID string, publicKey ed25519.PublicKey, now time.Time) (Response, error) {
	var response Response
	if decodeCanonical(document, maxResponseBytes, &response) != nil || response.Validate(request, policy, controllerKeyID, publicKey, now) != nil {
		response.Destroy()
		return Response{}, ErrUnavailable
	}
	return response, nil
}

func requestDigest(request Request) string {
	request.RequestDigest, request.Signature = "", ""
	document, _ := json.Marshal(request)
	domain := "sandbox-runtime/workload-certificate/request/v1\x00"
	if request.Protocol == PostgresClientProtocolID {
		domain = "sandbox-runtime/postgres-client-certificate/request/v1\x00"
	}
	digest := sha256.Sum256(append([]byte(domain), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func responseDigest(response Response) string {
	response.ResponseDigest, response.Signature = "", ""
	document, _ := json.Marshal(response)
	domain := "sandbox-runtime/workload-certificate/response/v1\x00"
	if response.Protocol == PostgresClientProtocolID {
		domain = "sandbox-runtime/postgres-client-certificate/response/v1\x00"
	}
	digest := sha256.Sum256(append([]byte(domain), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateCSR(document []byte, policy Policy) error {
	if policy.Purpose == PostgresClientPurpose {
		return ValidatePostgresClientCSR(document, policy.Postgres)
	}
	block, trailing := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		return ErrDenied
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil || request.Subject.String() != "" || len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 ||
		len(request.URIs) != 1 || request.URIs[0].String() != policy.URI || !equalStrings(request.DNSNames, policy.DNSNames) {
		return ErrDenied
	}
	switch request.PublicKeyAlgorithm {
	case x509.Ed25519, x509.ECDSA:
		return nil
	default:
		return ErrDenied
	}
}

func validateIssuedCertificate(response Response, request Request, policy Policy, now time.Time) error {
	csrBlock, _ := pem.Decode(request.CSRPEM)
	certificateBlock, trailing := pem.Decode(response.CertificatePEM)
	caBlock, caTrailing := pem.Decode(response.IssuingCAPEM)
	if csrBlock == nil || certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(certificateBlock.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 ||
		caBlock == nil || caBlock.Type != "CERTIFICATE" || len(caBlock.Headers) != 0 || len(bytes.TrimSpace(caTrailing)) != 0 {
		return ErrUnavailable
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return ErrUnavailable
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !publicKeysEqual(certificate.PublicKey, csr.PublicKey) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
		(policy.Purpose == PostgresClientPurpose && ValidatePostgresClientLeaf(certificate, policy.Postgres, now) != nil) ||
		(policy.Purpose == "" && (certificate.Subject.String() != "" || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != policy.URI ||
			!equalStrings(certificate.DNSNames, policy.DNSNames) || !equalUsages(certificate.ExtKeyUsage, policy.Usages) || certificate.KeyUsage != x509.KeyUsageDigitalSignature)) ||
		certificate.NotAfter.Sub(certificate.NotBefore) <= 0 || certificate.NotAfter.Sub(certificate.NotBefore) > time.Duration(request.RequestedTTLSeconds+120)*time.Second ||
		response.Serial != serialString(certificate.SerialNumber.Bytes()) || response.NotBefore != certificate.NotBefore.UTC().Format(time.RFC3339Nano) || response.NotAfter != certificate.NotAfter.UTC().Format(time.RFC3339Nano) {
		return ErrUnavailable
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA || certificate.CheckSignatureFrom(ca) != nil {
		return ErrUnavailable
	}
	if _, err := parseCertificateChain(response.CAChainPEM); err != nil {
		return ErrUnavailable
	}
	return nil
}

func equalUsages(actual []x509.ExtKeyUsage, expected []string) bool {
	values := make([]string, 0, len(actual))
	for _, usage := range actual {
		switch usage {
		case x509.ExtKeyUsageClientAuth:
			values = append(values, "client_auth")
		case x509.ExtKeyUsageServerAuth:
			values = append(values, "server_auth")
		default:
			return false
		}
	}
	sort.Strings(values)
	return equalStrings(values, expected)
}

func validateRevocationSnapshot(response Response, now time.Time) error {
	thisUpdate, errThis := parseTime(response.CRLThisUpdate)
	nextUpdate, errNext := parseTime(response.CRLNextUpdate)
	list, err := x509.ParseRevocationList(response.CRLDER)
	if err != nil || errThis != nil || errNext != nil || !list.ThisUpdate.Equal(thisUpdate) || !list.NextUpdate.Equal(nextUpdate) ||
		now.Before(thisUpdate) || !now.Before(nextUpdate) {
		return ErrUnavailable
	}
	return nil
}

func parseCertificateChain(document []byte) ([]*x509.Certificate, error) {
	remaining := document
	result := make([]*x509.Certificate, 0, 4)
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, trailing := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(result) >= 8 {
			return nil, ErrUnavailable
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return nil, ErrUnavailable
		}
		result = append(result, certificate)
		remaining = trailing
	}
	if len(result) == 0 {
		return nil, ErrUnavailable
	}
	return result, nil
}

func serialString(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = hex.EncodeToString([]byte{item})
	}
	return strings.Join(parts, ":")
}

func publicKeysEqual(left, right any) bool {
	leftDocument, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDocument, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDocument, rightDocument)
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validSignature(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == ed25519.SignatureSize && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func validDNS(value string) bool {
	return len(value) <= 253 && value == strings.ToLower(value) && dnsPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.Contains(value, "*") && net.ParseIP(value) == nil
}

func validUsages(values []string) bool {
	if len(values) < 1 || len(values) > 2 || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if value != "client_auth" && value != "server_auth" || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func sortedUnique(values []string, valid func(string) bool) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validPrincipalDelegation(requester, subject securityprincipal.Principal) bool {
	if requester.Digest() == subject.Digest() {
		return requester.Kind == securityprincipal.KindController && requester.Name == "certificate_controller"
	}
	if requester.Kind != securityprincipal.KindTLSAgent || requester.Role != subject.Role {
		return false
	}
	allowed := map[string]struct {
		kind securityprincipal.Kind
		name string
	}{
		"product_tls_agent":          {securityprincipal.KindRuntimeRole, "product"},
		"provider_tls_agent":         {securityprincipal.KindRuntimeRole, "provider"},
		"gateway_tls_agent":          {securityprincipal.KindRuntimeRole, "gateway"},
		"guest_tls_agent":            {securityprincipal.KindRuntimeRole, "guest"},
		"browser_tls_agent":          {securityprincipal.KindRuntimeRole, "browser"},
		"desktop_tls_agent":          {securityprincipal.KindRuntimeRole, "desktop"},
		"browser_executor_tls_agent": {securityprincipal.KindExecutorBackend, "browser_executor"},
		"desktop_executor_tls_agent": {securityprincipal.KindExecutorBackend, "desktop_executor"},
	}
	if subject.Kind == securityprincipal.KindEgressBroker {
		return requester.Name == subject.Name+"_tls_agent"
	}
	bound, ok := allowed[requester.Name]
	return ok && bound.kind == subject.Kind && bound.name == subject.Name
}

func decodeCanonical(document []byte, maximum int, target any) error {
	if len(document) < 1 || len(document) > maximum || rejectDuplicateJSON(document) != nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrInvalid
	}
	return nil
}

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var scan func(json.Token) error
	scan = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalid
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalid
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

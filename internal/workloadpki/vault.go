package workloadpki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxVaultTokenBytes    = 8 << 10
	maxVaultResponseBytes = 512 << 10
)

type VaultToken struct {
	Value     []byte
	ExpiresAt time.Time
	Revision  string
}

func (t *VaultToken) Destroy() {
	if t == nil {
		return
	}
	clear(t.Value)
	t.Value = nil
}

type VaultTokenSource interface {
	Token(context.Context) (VaultToken, error)
}

type VaultConfig struct {
	Endpoint                    string
	Mount                       string
	AllowedPolicies             map[string]string
	OperationTimeout            time.Duration
	Now                         func() time.Time
	RequireImmediateCompleteCRL bool
}

type IssuedCertificate struct {
	IssuerRevision string
	CertificatePEM []byte
	IssuingCAPEM   []byte
	CAChainPEM     []byte
	Serial         string
	NotBefore      time.Time
	NotAfter       time.Time
}

func (i *IssuedCertificate) Destroy() {
	if i == nil {
		return
	}
	clear(i.CertificatePEM)
	clear(i.IssuingCAPEM)
	clear(i.CAChainPEM)
	i.CertificatePEM, i.IssuingCAPEM, i.CAChainPEM = nil, nil, nil
}

type RevocationSnapshot struct {
	IssuerRevision string
	DER            []byte
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

func (s *RevocationSnapshot) Destroy() {
	if s == nil {
		return
	}
	clear(s.DER)
	s.DER = nil
}

type VaultClient struct {
	endpoint                    string
	mount                       string
	policies                    map[string]string
	client                      *http.Client
	tokens                      VaultTokenSource
	timeout                     time.Duration
	now                         func() time.Time
	requireImmediateCompleteCRL bool
}

func NewVaultClient(config VaultConfig, client *http.Client, tokens VaultTokenSource) (*VaultClient, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != config.Endpoint ||
		!namePattern.MatchString(config.Mount) || len(config.AllowedPolicies) < 1 || len(config.AllowedPolicies) > 128 || config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute ||
		config.Now == nil || config.Now().IsZero() || client == nil || tokens == nil {
		return nil, ErrUnavailable
	}
	policies := make(map[string]string, len(config.AllowedPolicies))
	for policy, vaultRole := range config.AllowedPolicies {
		if !namePattern.MatchString(policy) || !namePattern.MatchString(vaultRole) {
			return nil, ErrUnavailable
		}
		policies[policy] = vaultRole
	}
	clientCopy := *client
	clientCopy.Timeout = 0
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &VaultClient{endpoint: strings.TrimSuffix(config.Endpoint, "/"), mount: config.Mount, policies: policies,
		client: &clientCopy, tokens: tokens, timeout: config.OperationTimeout, now: config.Now,
		requireImmediateCompleteCRL: config.RequireImmediateCompleteCRL}, nil
}

func (c *VaultClient) Issue(ctx context.Context, policy Policy, csrPEM []byte, ttl time.Duration) (IssuedCertificate, error) {
	if c == nil || ctx == nil || policy.Validate() != nil || len(csrPEM) < 1 || len(csrPEM) > maxCSRBytes || ttl < time.Minute || ttl > time.Hour || int64(ttl/time.Second) > policy.MaxTTLSeconds || validateCSR(csrPEM, policy) != nil {
		return IssuedCertificate{}, ErrDenied
	}
	vaultRole, ok := c.policies[policy.ID]
	if !ok || vaultRole != policy.VaultRole {
		return IssuedCertificate{}, ErrDenied
	}
	body, err := json.Marshal(struct {
		CSR                  string `json:"csr"`
		TTL                  string `json:"ttl"`
		Format               string `json:"format"`
		RemoveRootsFromChain bool   `json:"remove_roots_from_chain"`
		ExcludeCNFromSANs    bool   `json:"exclude_cn_from_sans"`
	}{CSR: string(csrPEM), TTL: strconv.FormatInt(int64(ttl/time.Second), 10) + "s", Format: "pem", RemoveRootsFromChain: false, ExcludeCNFromSANs: true})
	if err != nil {
		return IssuedCertificate{}, ErrUnavailable
	}
	defer clear(body)
	document, _, err := c.request(ctx, http.MethodPost, "/v1/"+c.mount+"/sign/"+vaultRole, body, "application/json")
	if err != nil {
		return IssuedCertificate{}, err
	}
	defer clear(document)
	var data struct {
		AuthorityKeyID string   `json:"authority_key_id"`
		CAChain        []string `json:"ca_chain"`
		Certificate    string   `json:"certificate"`
		Expiration     int64    `json:"expiration"`
		IssuingCA      string   `json:"issuing_ca"`
		PrivateKey     string   `json:"private_key"`
		PrivateKeyType string   `json:"private_key_type"`
		SerialNumber   string   `json:"serial_number"`
	}
	if decodeVaultData(document, &data) != nil || !serialPattern.MatchString(data.AuthorityKeyID) || data.PrivateKey != "" || data.PrivateKeyType != "" || len(data.CAChain) < 1 || len(data.CAChain) > 8 || data.Expiration < 1 || !serialPattern.MatchString(data.SerialNumber) {
		return IssuedCertificate{}, ErrUnavailable
	}
	chain := []byte(strings.Join(data.CAChain, ""))
	issued := IssuedCertificate{CertificatePEM: []byte(data.Certificate), IssuingCAPEM: []byte(data.IssuingCA), CAChainPEM: chain, Serial: data.SerialNumber}
	certificateBlock, trailing := pem.Decode(issued.CertificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(certificateBlock.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
		issued.Destroy()
		return IssuedCertificate{}, ErrUnavailable
	}
	certificate, parseErr := x509.ParseCertificate(certificateBlock.Bytes)
	if parseErr != nil {
		issued.Destroy()
		return IssuedCertificate{}, ErrUnavailable
	}
	request := Request{RequestedTTLSeconds: int64(ttl / time.Second), CSRPEM: csrPEM}
	response := Response{CertificatePEM: issued.CertificatePEM, IssuingCAPEM: issued.IssuingCAPEM, CAChainPEM: issued.CAChainPEM,
		Serial: issued.Serial, NotBefore: certificate.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: certificate.NotAfter.UTC().Format(time.RFC3339Nano)}
	if data.Expiration != certificate.NotAfter.Unix() || validateIssuedCertificate(response, request, policy, c.now()) != nil {
		issued.Destroy()
		return IssuedCertificate{}, ErrUnavailable
	}
	issued.NotBefore, issued.NotAfter = certificate.NotBefore.UTC(), certificate.NotAfter.UTC()
	issuerDigest := sha256.Sum256(issued.IssuingCAPEM)
	issued.IssuerRevision = "vault-pki-" + hex.EncodeToString(issuerDigest[:8])
	return issued, nil
}

func (c *VaultClient) Revocations(ctx context.Context) (RevocationSnapshot, error) {
	if c == nil || ctx == nil {
		return RevocationSnapshot{}, ErrUnavailable
	}
	if c.requireImmediateCompleteCRL {
		if err := c.VerifyImmediateCompleteCRLConfig(ctx); err != nil {
			return RevocationSnapshot{}, err
		}
	}
	document, contentType, err := c.request(ctx, http.MethodGet, "/v1/"+c.mount+"/crl", nil, "application/pkix-crl")
	if err != nil {
		return RevocationSnapshot{}, err
	}
	if contentType != "application/pkix-crl" && contentType != "application/x-pkcs7-crl" && contentType != "application/octet-stream" {
		clear(document)
		return RevocationSnapshot{}, ErrUnavailable
	}
	list, err := x509.ParseRevocationList(document)
	if err != nil || list.ThisUpdate.IsZero() || list.NextUpdate.IsZero() || c.now().Before(list.ThisUpdate) || !c.now().Before(list.NextUpdate) {
		clear(document)
		return RevocationSnapshot{}, ErrUnavailable
	}
	digest := sha256.Sum256(document)
	return RevocationSnapshot{IssuerRevision: "vault-crl-" + hex.EncodeToString(digest[:8]), DER: document,
		ThisUpdate: list.ThisUpdate.UTC(), NextUpdate: list.NextUpdate.UTC()}, nil
}

// VerifyImmediateCompleteCRLConfig reads the actual Vault PKI mount policy.
// Vault's auto-rebuild mode does not publish every revoke into the complete
// CRL immediately; callers that promise peer-revocation drain must opt in to
// this check and grant only read access to config/crl, not rotate authority.
func (c *VaultClient) VerifyImmediateCompleteCRLConfig(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrUnavailable
	}
	document, contentType, err := c.request(ctx, http.MethodGet, "/v1/"+c.mount+"/config/crl", nil, "application/json")
	if err != nil {
		return err
	}
	defer clear(document)
	if contentType != "application/json" {
		return ErrUnavailable
	}
	var data map[string]json.RawMessage
	if decodeVaultData(document, &data) != nil {
		return ErrUnavailable
	}
	for _, key := range []string{"disable", "auto_rebuild", "enable_delta"} {
		value, ok := data[key]
		if !ok || !bytes.Equal(value, []byte("false")) {
			return ErrUnavailable
		}
	}
	return nil
}

func (c *VaultClient) Revoke(ctx context.Context, serial string) error {
	if c == nil || ctx == nil || !serialPattern.MatchString(serial) {
		return ErrDenied
	}
	body, err := json.Marshal(struct {
		Serial string `json:"serial_number"`
	}{Serial: serial})
	if err != nil {
		return ErrUnavailable
	}
	defer clear(body)
	document, _, err := c.request(ctx, http.MethodPost, "/v1/"+c.mount+"/revoke", body, "application/json")
	if err != nil {
		return err
	}
	defer clear(document)
	var data struct {
		RevocationTime    int64  `json:"revocation_time"`
		RevocationTimeRFC string `json:"revocation_time_rfc3339"`
		State             string `json:"state"`
	}
	if decodeVaultData(document, &data) != nil || data.RevocationTime < 1 || data.RevocationTimeRFC == "" || data.State != "revoked" {
		return ErrUnavailable
	}
	parsed, parseErr := time.Parse(time.RFC3339Nano, data.RevocationTimeRFC)
	if parseErr != nil || parsed.Unix() != data.RevocationTime || parsed.After(c.now().Add(time.Minute)) {
		return ErrUnavailable
	}
	return nil
}

func (c *VaultClient) request(ctx context.Context, method, requestPath string, body []byte, accept string) ([]byte, string, error) {
	operationContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	token, err := c.tokens.Token(operationContext)
	if err != nil {
		token.Destroy()
		return nil, "", normalizeVaultError(err)
	}
	defer token.Destroy()
	if !validVaultToken(token.Value) || !revisionPattern.MatchString(token.Revision) || !token.ExpiresAt.After(c.now()) {
		return nil, "", ErrUnavailable
	}
	request, err := http.NewRequestWithContext(operationContext, method, c.endpoint+requestPath, bytes.NewReader(body))
	if err != nil {
		return nil, "", ErrUnavailable
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("X-Vault-Token", string(token.Value))
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, "", normalizeVaultError(err)
	}
	defer response.Body.Close()
	document, readErr := io.ReadAll(io.LimitReader(response.Body, maxVaultResponseBytes+1))
	contentType, _, mimeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if readErr != nil || len(document) < 1 || len(document) > maxVaultResponseBytes || response.StatusCode != http.StatusOK || mimeErr != nil {
		clear(document)
		return nil, "", ErrUnavailable
	}
	return document, strings.ToLower(contentType), nil
}

func decodeVaultData(document []byte, target any) error {
	if len(document) < 1 || len(document) > maxVaultResponseBytes || rejectDuplicateJSON(document) != nil {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var response struct {
		RequestID     string          `json:"request_id"`
		LeaseID       string          `json:"lease_id"`
		Renewable     bool            `json:"renewable"`
		LeaseDuration int64           `json:"lease_duration"`
		Data          json.RawMessage `json:"data"`
		WrapInfo      json.RawMessage `json:"wrap_info"`
		Warnings      json.RawMessage `json:"warnings"`
		Auth          json.RawMessage `json:"auth"`
		MountType     string          `json:"mount_type"`
	}
	if decoder.Decode(&response) != nil || len(response.Data) < 2 {
		return ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	dataDecoder := json.NewDecoder(bytes.NewReader(response.Data))
	dataDecoder.DisallowUnknownFields()
	if dataDecoder.Decode(target) != nil {
		return ErrUnavailable
	}
	if err := dataDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func validVaultToken(value []byte) bool {
	if len(value) < 1 || len(value) > maxVaultTokenBytes {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func normalizeVaultError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}

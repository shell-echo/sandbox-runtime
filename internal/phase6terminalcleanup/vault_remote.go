package phase6terminalcleanup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const (
	operatorVaultHost = "vault.sandbox-runtime.test"
	operatorVaultURI  = "spiffe://sandbox-runtime.test/phase6-terminal-cleanup"
	operatorVaultPort = "8200"
	maxVaultReply     = 512 << 10
)

type VaultRemoteConfig struct {
	Plan              Plan
	Endpoint          string
	ServerCAPEM       []byte
	ClientCertificate []byte
	ClientPrivateKey  []byte
	Token             []byte
	TokenExpiresAt    time.Time
	Now               func() time.Time
}

type VaultRemote struct {
	client          *http.Client
	clientTransport *http.Transport
	token           *memoryTokenSource
	pki             *workloadpki.VaultClient
	issuerID        string
}

type memoryTokenSource struct {
	mu        sync.Mutex
	token     []byte
	expiresAt time.Time
	now       func() time.Time
	closed    bool
}

func (s *memoryTokenSource) Token(context.Context) (workloadpki.VaultToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.token) == 0 || !s.expiresAt.After(s.now()) {
		return workloadpki.VaultToken{}, ErrInvalid
	}
	return workloadpki.VaultToken{Value: bytes.Clone(s.token), ExpiresAt: s.expiresAt,
		Revision: "terminal-operator-1"}, nil
}

func (s *memoryTokenSource) Close() {
	s.mu.Lock()
	clear(s.token)
	s.token = nil
	s.closed = true
	s.mu.Unlock()
}

func NewVaultRemote(config VaultRemoteConfig) (*VaultRemote, error) {
	return newVaultRemote(config, nil)
}

// dial is test-only; production always resolves the one fixed Vault hostname
// within the operator-only network namespace.
func newVaultRemote(config VaultRemoteConfig, dial func(context.Context, string, string) (net.Conn, error)) (*VaultRemote, error) {
	if config.Plan.Validate() != nil || config.Endpoint != "https://"+operatorVaultHost+":"+operatorVaultPort ||
		config.Now == nil || config.Now().IsZero() || !config.TokenExpiresAt.After(config.Now()) ||
		config.TokenExpiresAt.After(config.Now().Add(15*time.Minute)) || !validOperatorToken(config.Token) {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.ServerCAPEM) {
		return nil, ErrInvalid
	}
	pair, err := tls.X509KeyPair(config.ClientCertificate, config.ClientPrivateKey)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != operatorVaultURI ||
		len(leaf.DNSNames) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return nil, ErrInvalid
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: config.Now()}); err != nil {
		return nil, ErrInvalid
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxIdleConns: 1,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			ServerName: operatorVaultHost, RootCAs: roots, Certificates: []tls.Certificate{pair}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(operatorVaultHost, operatorVaultPort) {
				return nil, ErrInvalid
			}
			if dial != nil {
				return dial(ctx, network, address)
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	token := &memoryTokenSource{token: bytes.Clone(config.Token), expiresAt: config.TokenExpiresAt, now: config.Now}
	pki, err := workloadpki.NewVaultClient(workloadpki.VaultConfig{Endpoint: config.Endpoint, Mount: "pki",
		AllowedPolicies:  map[string]string{"terminal-operator": "terminal-operator"},
		OperationTimeout: 10 * time.Second, Now: config.Now, RequireImmediateCompleteCRL: true,
		PeerIssuerSources: []workloadpki.VaultPeerIssuerSource{{SourceID: "general", Mount: "pki",
			IssuerID: config.Plan.GeneralIssuerID, IssuerDigest: config.Plan.GeneralIssuerDigest}}}, client, token)
	if err != nil {
		token.Close()
		transport.CloseIdleConnections()
		return nil, ErrInvalid
	}
	return &VaultRemote{client: client, clientTransport: transport, token: token, pki: pki,
		issuerID: config.Plan.GeneralIssuerID}, nil
}

func (v *VaultRemote) Close() {
	if v != nil {
		v.token.Close()
		v.clientTransport.CloseIdleConnections()
	}
}

func (v *VaultRemote) RevokeCertificate(ctx context.Context, serial string) error {
	if v == nil {
		return ErrInvalid
	}
	return v.pki.Revoke(ctx, serial)
}

func (v *VaultRemote) ReadCompleteCRL(ctx context.Context, issuerID string) ([]byte, []byte, error) {
	if v == nil || issuerID != v.pkiIssuerID() {
		return nil, nil, ErrInvalid
	}
	issuerDER, err := v.pki.PeerIssuerCertificate(ctx, "general")
	if err != nil {
		return nil, nil, ErrInvalid
	}
	snapshot, err := v.pki.PeerRevocations(ctx, "general", issuerDER)
	if err != nil {
		clear(issuerDER)
		return nil, nil, ErrInvalid
	}
	defer snapshot.Destroy()
	return issuerDER, bytes.Clone(snapshot.DER), nil
}

func (v *VaultRemote) pkiIssuerID() string {
	// The VaultClient's source map is intentionally private. The selected
	// issuer is retained in this adapter rather than accepted from a request.
	return v.issuerID
}

func (v *VaultRemote) LookupAccessor(ctx context.Context, accessor string) (TokenObservation, error) {
	if v == nil || !accessorPattern.MatchString(accessor) {
		return TokenObservation{}, ErrInvalid
	}
	body, _ := json.Marshal(struct {
		Accessor string `json:"accessor"`
	}{accessor})
	defer clear(body)
	status, document, err := v.request(ctx, "/v1/auth/token/lookup-accessor", body)
	if err != nil {
		return TokenObservation{}, ErrInvalid
	}
	defer clear(document)
	if status == http.StatusBadRequest && exactInvalidAccessor(document) {
		return TokenObservation{}, ErrAccessorAbsent
	}
	if status != http.StatusOK || rejectDuplicateJSON(document) != nil {
		return TokenObservation{}, ErrInvalid
	}
	var response struct {
		Data struct {
			Accessor  string            `json:"accessor"`
			Policies  []string          `json:"policies"`
			Meta      map[string]string `json:"meta"`
			Role      string            `json:"role"`
			Type      string            `json:"type"`
			Orphan    bool              `json:"orphan"`
			Renewable bool              `json:"renewable"`
			TTL       int64             `json:"ttl"`
		} `json:"data"`
	}
	if json.Unmarshal(document, &response) != nil || response.Data.Accessor != accessor {
		return TokenObservation{}, ErrInvalid
	}
	return TokenObservation{Accessor: response.Data.Accessor, Policies: response.Data.Policies,
		Metadata: response.Data.Meta, Role: response.Data.Role, Type: response.Data.Type,
		Orphan: response.Data.Orphan, Renewable: response.Data.Renewable, TTLSeconds: response.Data.TTL}, nil
}

func (v *VaultRemote) RevokeAccessor(ctx context.Context, accessor string) error {
	if v == nil || !accessorPattern.MatchString(accessor) {
		return ErrInvalid
	}
	body, _ := json.Marshal(struct {
		Accessor string `json:"accessor"`
	}{accessor})
	defer clear(body)
	status, document, err := v.request(ctx, "/v1/auth/token/revoke-accessor", body)
	clear(document)
	if err != nil || status != http.StatusNoContent {
		return ErrInvalid
	}
	return nil
}

func (v *VaultRemote) RevokeSelf(ctx context.Context) error {
	if v == nil {
		return ErrInvalid
	}
	status, document, err := v.request(ctx, "/v1/auth/token/revoke-self", []byte("{}"))
	clear(document)
	if err != nil || status != http.StatusNoContent {
		return ErrInvalid
	}
	v.token.Close()
	return nil
}

func (v *VaultRemote) request(ctx context.Context, path string, body []byte) (int, []byte, error) {
	if v == nil || ctx == nil || (path != "/v1/auth/token/lookup-accessor" &&
		path != "/v1/auth/token/revoke-accessor" && path != "/v1/auth/token/revoke-self") ||
		len(body) > 8<<10 {
		return 0, nil, ErrInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	token, err := v.token.Token(operationContext)
	if err != nil {
		return 0, nil, ErrInvalid
	}
	defer token.Destroy()
	request, err := http.NewRequestWithContext(operationContext, http.MethodPost,
		"https://"+operatorVaultHost+":"+operatorVaultPort+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, ErrInvalid
	}
	request.Header.Set("X-Vault-Token", string(token.Value))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return 0, nil, ErrInvalid
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, maxVaultReply+1))
	if err != nil || len(document) > maxVaultReply || response.StatusCode == http.StatusNoContent && len(document) != 0 {
		clear(document)
		return 0, nil, ErrInvalid
	}
	if response.StatusCode != http.StatusNoContent {
		contentType, _, mimeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mimeErr != nil || !strings.EqualFold(contentType, "application/json") {
			clear(document)
			return 0, nil, ErrInvalid
		}
	}
	return response.StatusCode, document, nil
}

func exactInvalidAccessor(document []byte) bool {
	if rejectDuplicateJSON(document) != nil {
		return false
	}
	var response struct {
		Errors []string `json:"errors"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || len(response.Errors) != 1 || response.Errors[0] != "invalid accessor" {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func validOperatorToken(token []byte) bool {
	if len(token) < 8 || len(token) > 8<<10 {
		return false
	}
	for _, value := range token {
		if value < '!' || value > '~' {
			return false
		}
	}
	return true
}

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if scanJSON(decoder) != nil {
				return ErrInvalid
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if scanJSON(decoder) != nil {
				return ErrInvalid
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

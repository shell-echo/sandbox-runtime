// Package phase6vaultbootstrap reads the actual fixed Vault PKI issuer during
// controlled Slice 6 bootstrap. Its output is desired-profile input, never a
// certificate issuance authority or a live-deployment observation.
package phase6vaultbootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrInvalidIssuer = errors.New("invalid Phase 6 Vault issuer bootstrap observation")

var issuerIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const maxVaultResponse = 64 << 10

// Issuer contains only public, verified PKI material. The UUID and digest are
// frozen before any workload admission; later leaves and CRLs are observations.
type Issuer struct {
	ID            string
	DER           []byte
	Digest        string
	CRLNumber     string
	CRLThisUpdate time.Time
	CRLNextUpdate time.Time
}

// ObserveIssuer uses an operator-owned, TLS 1.3 mTLS client and short-lived
// bootstrap token to discover Vault's current issuer once, then reads that
// immutable UUID's DER and complete CRL. It never returns or persists a token.
// The caller must independently bind the returned DER to the intended trust
// anchors and revoke its bootstrap authority before workload startup.
func ObserveIssuer(ctx context.Context, client *http.Client, endpoint, serverName, serverURI string, token []byte, now time.Time) (Issuer, error) {
	if !validIssuerObservationInput(ctx, client, endpoint, serverName, serverURI, token, now) {
		return Issuer{}, ErrInvalidIssuer
	}
	config, err := request(ctx, client, endpoint, serverName, serverURI, token, "/v1/pki/config/issuers", "application/json")
	if err != nil {
		return Issuer{}, err
	}
	var issuerConfig struct {
		Data struct {
			Default string `json:"default"`
		} `json:"data"`
	}
	if decodeVaultJSON(config, &issuerConfig) != nil || !issuerIDPattern.MatchString(issuerConfig.Data.Default) {
		return Issuer{}, ErrInvalidIssuer
	}
	id := issuerConfig.Data.Default
	observed, err := observeFixedIssuer(ctx, client, endpoint, serverName, serverURI, token, id, now)
	if err != nil {
		return Issuer{}, err
	}
	// Detect a default-issuer change during bootstrap. No workload uses the
	// mutable alias after this point; subsequent reads use only the fixed UUID.
	confirm, err := request(ctx, client, endpoint, serverName, serverURI, token, "/v1/pki/config/issuers", "application/json")
	if err != nil || decodeVaultJSON(confirm, &issuerConfig) != nil || issuerConfig.Data.Default != id {
		return Issuer{}, ErrInvalidIssuer
	}
	return observed, nil
}

// ObserveFixedIssuer reads a caller-selected immutable UUID. This is an
// operator bootstrap read, not workload authority or a mutable Vault alias.
// It permits observing both distinct issuers in the same PKI mount.
func ObserveFixedIssuer(ctx context.Context, client *http.Client, endpoint, serverName, serverURI string,
	token []byte, issuerID string, now time.Time) (Issuer, error) {
	if !validIssuerObservationInput(ctx, client, endpoint, serverName, serverURI, token, now) ||
		!issuerIDPattern.MatchString(issuerID) {
		return Issuer{}, ErrInvalidIssuer
	}
	return observeFixedIssuer(ctx, client, endpoint, serverName, serverURI, token, issuerID, now)
}

func validIssuerObservationInput(ctx context.Context, client *http.Client, endpoint, serverName, serverURI string,
	token []byte, now time.Time) bool {
	return ctx != nil && ctx.Err() == nil && client != nil && len(token) >= 8 && len(token) <= 8192 &&
		bytes.IndexAny(token, "\r\n\x00") < 0 && !now.IsZero() && validEndpoint(endpoint) &&
		serverName != "" && validServerURI(serverURI) && validClient(client, serverName)
}

func observeFixedIssuer(ctx context.Context, client *http.Client, endpoint, serverName, serverURI string,
	token []byte, id string, now time.Time) (Issuer, error) {
	crlConfig, err := request(ctx, client, endpoint, serverName, serverURI, token, "/v1/pki/config/crl", "application/json")
	if err != nil {
		return Issuer{}, err
	}
	var policy struct {
		Data struct {
			Disable     *bool `json:"disable"`
			AutoRebuild *bool `json:"auto_rebuild"`
			EnableDelta *bool `json:"enable_delta"`
		} `json:"data"`
	}
	if decodeVaultJSON(crlConfig, &policy) != nil || policy.Data.Disable == nil || *policy.Data.Disable ||
		policy.Data.AutoRebuild == nil || *policy.Data.AutoRebuild ||
		policy.Data.EnableDelta == nil || *policy.Data.EnableDelta {
		return Issuer{}, ErrInvalidIssuer
	}
	base := "/v1/pki/issuer/" + id
	der, err := request(ctx, client, endpoint, serverName, serverURI, token, base+"/der", "application/pkix-cert", "application/octet-stream")
	if err != nil {
		return Issuer{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return Issuer{}, ErrInvalidIssuer
	}
	crlDER, err := request(ctx, client, endpoint, serverName, serverURI, token, base+"/crl/der", "application/pkix-crl", "application/octet-stream")
	if err != nil {
		return Issuer{}, err
	}
	list, err := x509.ParseRevocationList(crlDER)
	if err != nil || list.Number == nil || list.Number.Sign() < 0 || list.ThisUpdate.IsZero() ||
		list.NextUpdate.IsZero() || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) ||
		list.CheckSignatureFrom(certificate) != nil ||
		(len(certificate.SubjectKeyId) != 0 && !bytes.Equal(list.AuthorityKeyId, certificate.SubjectKeyId)) {
		return Issuer{}, ErrInvalidIssuer
	}
	sum := sha256.Sum256(der)
	return Issuer{ID: id, DER: bytes.Clone(der), Digest: "sha256:" + hex.EncodeToString(sum[:]),
		CRLNumber: list.Number.String(), CRLThisUpdate: list.ThisUpdate.UTC(), CRLNextUpdate: list.NextUpdate.UTC()}, nil
}

func validEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.HasSuffix(raw, "/")
}

func validServerURI(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host == "sandbox-runtime.test" &&
		parsed.User == nil && parsed.Path == "/external/vault" && parsed.RawQuery == "" &&
		parsed.Fragment == "" && parsed.String() == raw
}

func validClient(client *http.Client, serverName string) bool {
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || client.Timeout <= 0 || client.Timeout > 30*time.Second ||
		transport.Proxy != nil || transport.DialContext != nil || transport.DialTLSContext != nil ||
		transport.DialTLS != nil || transport.TLSNextProto != nil {
		return false
	}
	config := transport.TLSClientConfig
	return !config.InsecureSkipVerify && config.RootCAs != nil && config.ServerName == serverName &&
		config.MinVersion == tls.VersionTLS13 && config.MaxVersion == tls.VersionTLS13 &&
		(len(config.Certificates) == 1 || config.GetClientCertificate != nil)
}

func request(ctx context.Context, client *http.Client, endpoint, serverName, serverURI string, token []byte, path string, contentTypes ...string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
	if err != nil {
		return nil, ErrInvalidIssuer
	}
	req.Header.Set("X-Vault-Token", string(token))
	closed := *client
	closed.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := closed.Do(req)
	if err != nil {
		return nil, ErrInvalidIssuer
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 ||
		len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 ||
		response.TLS.PeerCertificates[0].VerifyHostname(serverName) != nil ||
		!exactVaultServerIdentity(response.TLS.PeerCertificates[0], serverURI) {
		return nil, ErrInvalidIssuer
	}
	contentType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	validType := false
	for _, allowed := range contentTypes {
		if contentType == allowed {
			validType = true
		}
	}
	if !validType {
		return nil, ErrInvalidIssuer
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxVaultResponse+1))
	if err != nil || len(document) == 0 || len(document) > maxVaultResponse {
		return nil, ErrInvalidIssuer
	}
	return document, nil
}

func exactVaultServerIdentity(leaf *x509.Certificate, serverURI string) bool {
	return leaf != nil && len(leaf.URIs) == 1 && leaf.URIs[0].String() == serverURI &&
		len(leaf.ExtKeyUsage) == 1 && leaf.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth &&
		len(leaf.UnknownExtKeyUsage) == 0 && leaf.KeyUsage == x509.KeyUsageDigitalSignature
}

func decodeVaultJSON(document []byte, target any) error {
	if len(document) == 0 || len(document) > maxVaultResponse || duplicateJSONMembers(document) != nil {
		return ErrInvalidIssuer
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrInvalidIssuer
	}
	return nil
}

func duplicateJSONMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrInvalidIssuer
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || seen[key] {
					return ErrInvalidIssuer
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrInvalidIssuer
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(map[json.Delim]byte{'{': '}', '[': ']'}[delimiter]) {
			return ErrInvalidIssuer
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidIssuer
	}
	return nil
}

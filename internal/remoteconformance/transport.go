package remoteconformance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxTargetBytes           = 512
	maxCABytes               = 256 << 10
	maxCertificateBytes      = 64 << 10
	maxPrivateKeyBytes       = 64 << 10
	maxResponseBodyBytes     = 2 << 20
	maxResponseHeaderBytes   = 64 << 10
	maxCACertificates        = 32
	maxCertificateChain      = 16
	maxURIIdentityBytes      = 2048
	maxProviderRevisionRunes = 200
	maxProviderRevisionBytes = maxProviderRevisionRunes * utf8.UTFMax
	requestTimeout           = 20 * time.Second
	connectionTimeout        = 5 * time.Second
)

type schemaValidator interface {
	Validate(string, []byte) error
}

type executor struct {
	target                   *url.URL
	address                  string
	tlsConfig                *tls.Config
	client                   *http.Client
	transport                *http.Transport
	noCertClient             *http.Client
	noCertTransport          *http.Transport
	deniedClient             *http.Client
	deniedTransport          *http.Transport
	validator                schemaValidator
	baseline                 []byte
	expectedProviderRevision string
	providerRevision         string
	capabilityDigest         string
	unsafeMethodProbesSent   bool
}

type wireResponse struct {
	status int
	header http.Header
	body   []byte
	tls    *tls.ConnectionState
}

func newExecutor(options Options, validator schemaValidator) (*executor, error) {
	target, address, serverName, err := validateTarget(options.Target, options.ServerName)
	if err != nil || validator == nil || !validExpectedProviderRevision(options.ProviderRevision) {
		return nil, failure("invalid_configuration")
	}
	paths := []string{
		options.CAFile, options.ClientCAFile, options.ClientCert,
		options.ClientKey, options.DeniedClientCert, options.DeniedClientKey,
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for index, path := range paths {
		if !filepath.IsAbs(path) {
			return nil, failure("invalid_configuration")
		}
		paths[index] = filepath.Clean(path)
		if _, duplicate := seenPaths[paths[index]]; duplicate {
			return nil, failure("invalid_configuration")
		}
		seenPaths[paths[index]] = struct{}{}
	}
	serverRoots, err := loadCABundle(paths[0], time.Now())
	if err != nil {
		return nil, failure("invalid_configuration")
	}
	now := time.Now()
	clientRoots, err := loadCABundle(paths[1], now)
	if err != nil {
		return nil, failure("invalid_configuration")
	}
	certificate, admittedIdentity, admittedRoot, err := loadClientIdentity(paths[2], paths[3], clientRoots, now)
	if err != nil {
		return nil, failure("invalid_configuration")
	}
	deniedCertificate, deniedIdentity, deniedRoot, err := loadClientIdentity(paths[4], paths[5], clientRoots, now)
	if err != nil || admittedIdentity == deniedIdentity || admittedRoot != deniedRoot {
		return nil, failure("invalid_configuration")
	}

	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: serverRoots, ServerName: serverName, NextProtos: []string{"http/1.1"},
	}
	withCertificate := baseTLS.Clone()
	withCertificate.Certificates = []tls.Certificate{certificate}
	withDeniedCertificate := baseTLS.Clone()
	withDeniedCertificate.Certificates = []tls.Certificate{deniedCertificate}
	transport := newTransport(withCertificate)
	noCertTransport := newTransport(baseTLS.Clone())
	deniedTransport := newTransport(withDeniedCertificate)
	return &executor{
		target: target, address: address, tlsConfig: withCertificate,
		client: newHTTPClient(transport), transport: transport,
		noCertClient: newHTTPClient(noCertTransport), noCertTransport: noCertTransport,
		deniedClient: newHTTPClient(deniedTransport), deniedTransport: deniedTransport,
		validator: validator, expectedProviderRevision: options.ProviderRevision,
	}, nil
}

func newTransport(config *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 10 * time.Second,
		TLSHandshakeTimeout: connectionTimeout, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes, TLSClientConfig: config,
	}
}

func newHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (e *executor) close() {
	e.transport.CloseIdleConnections()
	e.noCertTransport.CloseIdleConnections()
	e.deniedTransport.CloseIdleConnections()
}

func (e *executor) runCase(ctx context.Context, id string) error {
	switch id {
	case "remote-capability-discovery-mtls-success":
		return e.mtlsSuccess(ctx)
	case "remote-capability-discovery-client-certificate-required":
		return e.clientCertificateRequired(ctx)
	case "remote-capability-discovery-schema":
		return e.schema(ctx)
	case "remote-capability-discovery-immutable":
		return e.immutable(ctx)
	case "remote-capability-discovery-empty-request":
		return e.emptyRequest(ctx)
	case "remote-capability-discovery-get-only":
		return e.getOnly(ctx)
	default:
		return failure("unknown_case")
	}
}

func (e *executor) mtlsSuccess(ctx context.Context) error {
	result, err := e.request(ctx, e.client, http.MethodGet, "/v1/capabilities", nil, 0)
	if err != nil {
		return err
	}
	if result.status != http.StatusOK {
		return failure("unexpected_status")
	}
	if result.tls == nil || result.tls.Version != tls.VersionTLS13 || !result.tls.HandshakeComplete {
		return failure("tls_policy_mismatch")
	}
	e.baseline = append([]byte(nil), result.body...)
	e.capabilityDigest = digestString(string(result.body))
	return nil
}

func (e *executor) clientCertificateRequired(ctx context.Context) error {
	e.noCertTransport.CloseIdleConnections()
	status, receivedHTTPResponse, rejectionErr := e.rejectionRequest(ctx, e.noCertClient)
	if rejectionErr != nil && (errors.Is(rejectionErr, context.Canceled) || errors.Is(rejectionErr, context.DeadlineExceeded)) {
		return rejectionErr
	}
	if err := e.admittedHealthProbe(ctx); err != nil {
		return err
	}
	if rejectionErr == nil || receivedHTTPResponse || status != 0 {
		return failure("client_certificate_not_required")
	}

	e.deniedTransport.CloseIdleConnections()
	status, receivedHTTPResponse, rejectionErr = e.rejectionRequest(ctx, e.deniedClient)
	if rejectionErr != nil && (errors.Is(rejectionErr, context.Canceled) || errors.Is(rejectionErr, context.DeadlineExceeded)) {
		return rejectionErr
	}
	if err := e.admittedHealthProbe(ctx); err != nil {
		return err
	}
	if receivedHTTPResponse {
		if rejectionErr != nil || status != http.StatusForbidden {
			return failure("client_identity_not_enforced")
		}
	} else if rejectionErr == nil {
		return failure("client_identity_not_enforced")
	}
	return nil
}

func (e *executor) rejectionRequest(ctx context.Context, client *http.Client) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, contextFailure(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.target.String()+"/v1/capabilities", nil)
	if err != nil {
		return 0, false, failure("request_construction_failed")
	}
	response, err := client.Do(request)
	if ctx.Err() != nil {
		if response != nil {
			response.Body.Close()
		}
		return 0, response != nil, contextFailure(ctx.Err())
	}
	if response == nil {
		return 0, false, err
	}
	defer response.Body.Close()
	return response.StatusCode, true, err
}

func (e *executor) admittedHealthProbe(ctx context.Context) error {
	// Force a fresh admitted handshake so an outage cannot satisfy a negative
	// identity probe through a coincidental transport failure.
	e.transport.CloseIdleConnections()
	health, err := e.request(ctx, e.client, http.MethodGet, "/v1/capabilities", nil, 0)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return failure("target_unavailable")
	}
	if health.status != http.StatusOK {
		return failure("target_unavailable")
	}
	return nil
}

func (e *executor) schema(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return contextFailure(err)
	}
	if len(e.baseline) == 0 {
		return failure("baseline_unavailable")
	}
	if err := validateSingleJSONValueWithUniqueMembers(e.baseline); err != nil {
		return failure("schema_validation_failed")
	}
	if err := e.validator.Validate("provider-capabilities.schema.json", e.baseline); err != nil {
		return failure("schema_validation_failed")
	}
	var document struct {
		ProviderRevisionID string `json:"provider_revision_id"`
	}
	if err := json.Unmarshal(e.baseline, &document); err != nil || document.ProviderRevisionID == "" {
		return failure("schema_validation_failed")
	}
	e.providerRevision = document.ProviderRevisionID
	if e.providerRevision != e.expectedProviderRevision {
		return failure("provider_revision_mismatch")
	}
	return nil
}

func (e *executor) immutable(ctx context.Context) error {
	if len(e.baseline) == 0 {
		return failure("baseline_unavailable")
	}
	const reads = 8
	for range reads {
		result, err := e.request(ctx, e.client, http.MethodGet, "/v1/capabilities", nil, 0)
		if err != nil {
			return err
		}
		if result.status != http.StatusOK || !bytes.Equal(result.body, e.baseline) {
			return failure("capability_snapshot_changed")
		}
	}
	return nil
}

func (e *executor) emptyRequest(ctx context.Context) error {
	tests := []struct {
		path          string
		body          io.Reader
		contentLength int64
	}{
		{path: "/v1/capabilities?unexpected=value", contentLength: 0},
		{path: "/v1/capabilities?", contentLength: 0},
		{path: "/v1/capabilities", body: strings.NewReader("x"), contentLength: 1},
		{path: "/v1/capabilities", body: strings.NewReader("x"), contentLength: -1},
	}
	for _, test := range tests {
		result, err := e.request(ctx, e.client, http.MethodGet, test.path, test.body, test.contentLength)
		if err != nil {
			return err
		}
		if result.status != http.StatusBadRequest {
			return failure("empty_request_rule_not_enforced")
		}
	}
	result, err := e.rawRequest(ctx, "GET /v1/capabilities HTTP/1.1\r\nHost: "+e.target.Host+"\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n")
	if err != nil {
		return err
	}
	if result.status != http.StatusNotImplemented {
		return failure("unsupported_transfer_coding_not_rejected")
	}
	return nil
}

func (e *executor) getOnly(ctx context.Context) error {
	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		if err := ctx.Err(); err != nil {
			return contextFailure(err)
		}
		e.unsafeMethodProbesSent = true
		result, err := e.request(ctx, e.client, method, "/v1/capabilities", nil, 0)
		if err != nil {
			return err
		}
		if result.status != http.StatusMethodNotAllowed || result.header.Get("Allow") != http.MethodGet {
			return failure("get_only_rule_not_enforced")
		}
	}
	return nil
}

func (e *executor) request(ctx context.Context, client *http.Client, method, path string, body io.Reader, contentLength int64) (wireResponse, error) {
	if err := ctx.Err(); err != nil {
		return wireResponse{}, contextFailure(err)
	}
	request, err := http.NewRequestWithContext(ctx, method, e.target.String()+path, body)
	if err != nil {
		return wireResponse{}, failure("request_construction_failed")
	}
	request.ContentLength = contentLength
	if body != nil && contentLength < 0 {
		request.TransferEncoding = []string{"chunked"}
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("transport_failed")
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("response_read_failed")
	}
	if len(document) > maxResponseBodyBytes {
		return wireResponse{}, failure("response_body_oversized")
	}
	if len(document) > 0 {
		mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/json" {
			return wireResponse{}, failure("response_media_type_invalid")
		}
	}
	return wireResponse{status: response.StatusCode, header: response.Header.Clone(), body: document, tls: response.TLS}, nil
}

func (e *executor) rawRequest(ctx context.Context, document string) (wireResponse, error) {
	dialer := &net.Dialer{Timeout: connectionTimeout}
	connection, err := (&tls.Dialer{NetDialer: dialer, Config: e.tlsConfig.Clone()}).DialContext(ctx, "tcp", e.address)
	if err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("transport_failed")
	}
	defer connection.Close()
	stopCancelClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancelClose()
	deadline := time.Now().Add(requestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("transport_failed")
	}
	if _, err := io.WriteString(connection, document); err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("transport_failed")
	}
	reader := bufio.NewReader(io.LimitReader(connection, maxResponseHeaderBytes+maxResponseBodyBytes+1))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, contextFailure(ctx.Err())
		}
		return wireResponse{}, failure("response_read_failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if ctx.Err() != nil {
		return wireResponse{}, contextFailure(ctx.Err())
	}
	if err != nil || len(body) > maxResponseBodyBytes {
		return wireResponse{}, failure("response_body_oversized")
	}
	return wireResponse{status: response.StatusCode, header: response.Header.Clone(), body: body}, nil
}

func validateTarget(raw, configuredServerName string) (*url.URL, string, string, error) {
	if raw == "" || len(raw) > maxTargetBytes || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t") {
		return nil, "", "", errors.New("invalid target")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, "", "", errors.New("invalid target")
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.ContainsAny(parsed.Host, " \r\n\t") {
		return nil, "", "", errors.New("invalid target")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	} else if number, parseErr := strconv.Atoi(port); parseErr != nil || number < 1 || number > 65535 {
		return nil, "", "", errors.New("invalid target")
	}
	serverName := configuredServerName
	if serverName == "" || len(serverName) > 253 || strings.TrimSpace(serverName) != serverName || strings.ContainsAny(serverName, " /\\\r\n\t") ||
		(strings.Contains(serverName, ":") && net.ParseIP(serverName) == nil) {
		return nil, "", "", errors.New("invalid server name")
	}
	return parsed, net.JoinHostPort(hostname, port), serverName, nil
}

func validExpectedProviderRevision(revision string) bool {
	return revision != "" && strings.TrimSpace(revision) != "" && utf8.ValidString(revision) &&
		len(revision) <= maxProviderRevisionBytes && utf8.RuneCountInString(revision) <= maxProviderRevisionRunes
}

func validateSingleJSONValueWithUniqueMembers(document []byte) error {
	if !utf8.Valid(document) {
		return errors.New("JSON must be valid UTF-8")
	}
	if err := validateUnicodeEscapes(document); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err == nil {
		return errors.New("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func validateUnicodeEscapes(document []byte) error {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(document) {
				continue
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			codePoint, ok := decodeHexQuad(document, index+2)
			if !ok {
				continue
			}
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+11 >= len(document) || document[index+6] != '\\' || document[index+7] != 'u' {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				low, ok := decodeHexQuad(document, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				index += 11
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return errors.New("JSON contains an invalid Unicode surrogate escape")
			default:
				index += 5
			}
		}
	}
	return nil
}

func decodeHexQuad(document []byte, start int) (uint16, bool) {
	if start+4 > len(document) {
		return 0, false
	}
	var value uint16
	for _, digit := range document[start : start+4] {
		value *= 16
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func loadCABundle(path string, now time.Time) (*x509.CertPool, error) {
	contents, err := readBoundedRegularFile(path, maxCABytes, false)
	if err != nil {
		return nil, err
	}
	certificates, err := parseCertificatePEM(contents, maxCACertificates)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		if !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return nil, errors.New("invalid CA certificate")
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}

func loadClientIdentity(certPath, keyPath string, roots *x509.CertPool, now time.Time) (tls.Certificate, string, [sha256.Size]byte, error) {
	certificatePEM, err := readBoundedRegularFile(certPath, maxCertificateBytes, false)
	if err != nil {
		return tls.Certificate{}, "", [sha256.Size]byte{}, err
	}
	privateKeyPEM, err := readBoundedRegularFile(keyPath, maxPrivateKeyBytes, true)
	if err != nil || bytes.Equal(certificatePEM, privateKeyPEM) {
		return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("invalid client key pair")
	}
	parsed, err := parseCertificatePEM(certificatePEM, maxCertificateChain)
	if err != nil {
		return tls.Certificate{}, "", [sha256.Size]byte{}, err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) != len(parsed) {
		return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("invalid client key pair")
	}
	leaf := parsed[0]
	if !hasExplicitClientAuth(leaf) || len(leaf.URIs) != 1 || !validExactAbsoluteURI(leaf.URIs[0]) {
		return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("invalid client certificate identity")
	}
	intermediates := x509.NewCertPool()
	for _, intermediate := range parsed[1:] {
		intermediates.AddCert(intermediate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("client certificate chain verification failed")
	}
	verifiedRoots := make(map[[sha256.Size]byte]struct{})
	for _, chain := range chains {
		if len(chain) == 0 {
			return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("empty verified client certificate chain")
		}
		verifiedRoots[sha256.Sum256(chain[len(chain)-1].Raw)] = struct{}{}
	}
	if len(verifiedRoots) != 1 {
		return tls.Certificate{}, "", [sha256.Size]byte{}, errors.New("client certificate has ambiguous trust roots")
	}
	var verifiedRoot [sha256.Size]byte
	for root := range verifiedRoots {
		verifiedRoot = root
	}
	certificate.Leaf = leaf
	return certificate, leaf.URIs[0].String(), verifiedRoot, nil
}

func parseCertificatePEM(contents []byte, maximum int) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace(contents)
	certificates := make([]*x509.Certificate, 0, 1)
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) || len(certificates) >= maximum {
			return nil, errors.New("invalid certificate PEM bundle")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate PEM bundle")
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, errors.New("empty certificate PEM bundle")
	}
	return certificates, nil
}

func hasExplicitClientAuth(certificate *x509.Certificate) bool {
	found := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return false
		}
		if usage == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	return found
}

func validExactAbsoluteURI(identity *url.URL) bool {
	if identity == nil || !identity.IsAbs() || identity.Scheme == "" || identity.Fragment != "" {
		return false
	}
	encoded := identity.String()
	if len(encoded) < 1 || len(encoded) > maxURIIdentityBytes || !utf8.ValidString(encoded) || strings.TrimSpace(encoded) != encoded {
		return false
	}
	parsed, err := url.Parse(encoded)
	return err == nil && parsed.IsAbs() && parsed.String() == encoded
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object member")
			}
			if _, duplicate := members[key]; duplicate {
				return errors.New("duplicate JSON object member")
			}
			members[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, ']')
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("invalid file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("invalid file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() < 1 || opened.Size() > maximum || (private && opened.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("invalid file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, errors.New("invalid file")
	}
	return contents, nil
}

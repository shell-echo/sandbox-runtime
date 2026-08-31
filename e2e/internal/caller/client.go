package caller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

type providerClient struct {
	config Config
	http   *http.Client
	signer *signer
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func newProviderClient(config Config, transportIdentity, signingIdentity IdentityConfig) (*providerClient, error) {
	httpClient, err := newMTLSClient(config.CAFile, transportIdentity.CertificateFile, transportIdentity.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	requestSigner, err := loadSigner(signingIdentity)
	if err != nil {
		httpClient.CloseIdleConnections()
		return nil, err
	}
	return &providerClient{config: config, http: httpClient, signer: requestSigner}, nil
}

func newMTLSClient(caFile, certificateFile, privateKeyFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read caller CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("caller CA bundle is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load caller mTLS key pair: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate},
		},
		ForceAttemptHTTP2: true, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, nil
}

func (c *providerClient) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *providerClient) capabilities(ctx context.Context) (Capabilities, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.ProviderBaseURL+"/v1/capabilities", nil)
	if err != nil {
		return Capabilities{}, nil, err
	}
	result, err := c.do(request)
	if err != nil {
		return Capabilities{}, nil, err
	}
	if result.Status != http.StatusOK {
		return Capabilities{}, result.Body, unexpectedStatus("capabilities", result, http.StatusOK)
	}
	var capabilities Capabilities
	if err := decodeStrict(result.Body, &capabilities); err != nil {
		return Capabilities{}, result.Body, err
	}
	if err := checkNoBackendDisclosure(result.Body); err != nil {
		return Capabilities{}, result.Body, err
	}
	return capabilities, result.Body, nil
}

func (c *providerClient) prepare(method, path string, body map[string]any, binding admissionBinding) (preparedRequest, error) {
	return c.signer.prepare(c.config, method, path, body, binding)
}

func (c *providerClient) send(ctx context.Context, prepared preparedRequest) (response, error) {
	var body io.Reader
	if prepared.Body != nil {
		body = bytes.NewReader(prepared.Body)
	}
	request, err := http.NewRequestWithContext(ctx, prepared.Method, c.config.ProviderBaseURL+prepared.Path, body)
	if err != nil {
		return response{}, err
	}
	request.Header.Set("Authorization", prepared.Authorization)
	request.Header.Set(admissionContextHeader, prepared.AdmissionContext)
	if prepared.Body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return c.do(request)
}

func (c *providerClient) do(request *http.Request) (response, error) {
	httpResponse, err := c.http.Do(request)
	if err != nil {
		return response{}, err
	}
	defer httpResponse.Body.Close()
	limited := io.LimitReader(httpResponse.Body, maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return response{}, err
	}
	if len(body) > maxResponseBytes {
		return response{}, errors.New("Provider response exceeds caller bound")
	}
	if len(body) > 0 && !strings.HasPrefix(strings.ToLower(httpResponse.Header.Get("Content-Type")), "application/json") {
		return response{}, errors.New("Provider returned a non-JSON response")
	}
	return response{Status: httpResponse.StatusCode, Header: httpResponse.Header.Clone(), Body: body}, nil
}

func unexpectedStatus(name string, result response, expected ...int) error {
	var standard StandardError
	_ = decodeStrict(result.Body, &standard)
	return fmt.Errorf("%s status = %d, want %v (code=%s)", name, result.Status, expected, standard.Code)
}

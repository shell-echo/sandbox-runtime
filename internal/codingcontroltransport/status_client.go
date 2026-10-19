package codingcontroltransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
)

var ErrInvalidStatusClient = errors.New("invalid Coding Control status client")

type statusClientConfig struct {
	Origin                  string
	ProviderPrincipalDigest string
	ProfileDigest           string
	ControlPolicyDigest     string
	OperationTimeout        time.Duration
	Transport               *http.Transport
}

type statusClient struct {
	config statusClientConfig
	client *http.Client
}

// This constructor is deliberately private until a complete Profile-v2
// factory supplies the exact Control edge and non-optional peer CRL guard.
// A caller cannot inject an HTTP client, redirect policy or fallback dialer.
func newStatusClient(config statusClientConfig) (*statusClient, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" ||
		origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.User != nil || origin.Fragment != "" || origin.String() != config.Origin ||
		!statusDigestPattern.MatchString(config.ProviderPrincipalDigest) ||
		!statusDigestPattern.MatchString(config.ProfileDigest) ||
		!statusDigestPattern.MatchString(config.ControlPolicyDigest) ||
		config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second ||
		config.Transport == nil || config.Transport.TLSClientConfig == nil ||
		config.Transport.TLSClientConfig.MinVersion < tls.VersionTLS13 ||
		config.Transport.TLSClientConfig.InsecureSkipVerify ||
		config.Transport.TLSClientConfig.RootCAs == nil ||
		config.Transport.TLSClientConfig.VerifyConnection == nil ||
		(len(config.Transport.TLSClientConfig.Certificates) == 0 &&
			config.Transport.TLSClientConfig.GetClientCertificate == nil) ||
		config.Transport.Proxy != nil || config.Transport.DialContext == nil ||
		config.Transport.DialTLSContext == nil || !config.Transport.DisableKeepAlives {
		return nil, ErrInvalidStatusClient
	}
	transport := config.Transport.Clone()
	// Preserve response framing/encoding for the bounded protocol decoder.
	// Automatic gzip decoding would hide a peer's Content-Encoding header.
	transport.DisableCompression = true
	config.Transport = nil
	return &statusClient{config: config, client: &http.Client{Transport: transport,
		Timeout: config.OperationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrInvalidStatusClient
		}}}, nil
}

func (c *statusClient) Read(ctx context.Context,
	request codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	if request.Action != codingcontrolprotocol.ActionStatus {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	return c.exchange(ctx, request)
}

// exchange is shared only by the read-only entry and the closed typed
// mutation dispatcher. There is no exported generic request/Doer port.
func (c *statusClient) exchange(ctx context.Context, request codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil ||
		request.Create.ProfileDigest != c.config.ProfileDigest ||
		request.Create.ControlPolicyDigest != c.config.ControlPolicyDigest ||
		request.Validate(time.Now().UTC(), c.config.ProviderPrincipalDigest) != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	document, err := codingcontrolprotocol.EncodeRequest(request)
	if err != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	defer clear(document)
	operation, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(operation, http.MethodPost,
		c.config.Origin+CodingStatusPath, bytes.NewReader(document))
	if err != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	// Even redirects that preserve POST and a replayable body cannot resend an
	// original mutation. The admitted transport also disables keep-alives.
	httpRequest.GetBody = nil
	httpRequest.Close = true
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := c.client.Do(httpRequest)
	if err != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK ||
		len(httpResponse.Header.Values("Content-Type")) != 1 ||
		httpResponse.Header.Get("Content-Type") != "application/json" ||
		httpResponse.Header.Get("Content-Encoding") != "" ||
		httpResponse.ContentLength < 0 || httpResponse.ContentLength > codingcontrolprotocol.MaxResponseBytes ||
		len(httpResponse.TransferEncoding) != 0 {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body,
		codingcontrolprotocol.MaxResponseBytes+1))
	defer clear(responseBody)
	closeErr := httpResponse.Body.Close()
	if err != nil || closeErr != nil || int64(len(responseBody)) != httpResponse.ContentLength || len(responseBody) > codingcontrolprotocol.MaxResponseBytes ||
		operation.Err() != nil || ctx.Err() != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	response, err := codingcontrolprotocol.DecodeResponse(responseBody, request)
	if err != nil || operation.Err() != nil || ctx.Err() != nil {
		return codingcontrolprotocol.Response{}, ErrInvalidStatusClient
	}
	return response, nil
}

func (c *statusClient) Close() {
	if c != nil && c.client != nil {
		c.client.CloseIdleConnections()
	}
}

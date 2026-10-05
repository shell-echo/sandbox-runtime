package artifactscanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

type RemoteConfig struct {
	BaseURL               string
	GuardedTransport      *http.Transport
	Peer                  connectiondrain.PeerMonitor
	ProfileDigest         string
	ExpectedRuleSetDigest string
	OperationTimeout      time.Duration
	Clock                 func() time.Time
}

// RemoteMalwareChecker is the coding Provider's private mTLS client. The
// Provider's local passive-json policy runs first; the scanner independently
// returns both policy and malware results for the exact same bounded bytes.
type RemoteMalwareChecker struct {
	config RemoteConfig
	client *http.Client
	base   string
}

func NewRemoteMalwareChecker(config RemoteConfig) (*RemoteMalwareChecker, error) {
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" || parsed.Host == "" {
		return nil, ErrInvalidScanProtocol
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || net.ParseIP(host) == nil || port == "" ||
		config.GuardedTransport == nil || !config.GuardedTransport.DisableKeepAlives ||
		config.GuardedTransport.DialContext == nil || config.GuardedTransport.DialTLSContext == nil ||
		config.GuardedTransport.TLSClientConfig == nil ||
		config.GuardedTransport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		config.GuardedTransport.TLSClientConfig.InsecureSkipVerify ||
		config.GuardedTransport.TLSClientConfig.VerifyConnection == nil ||
		config.Peer == nil || config.Peer.PollInterval() < 100*time.Millisecond ||
		!scanDigestPattern.MatchString(config.ProfileDigest) ||
		!scanDigestPattern.MatchString(config.ExpectedRuleSetDigest) ||
		config.OperationTimeout < time.Second || config.OperationTimeout > maxAuthorityAge || config.Clock == nil {
		return nil, ErrInvalidScanProtocol
	}
	transport := config.GuardedTransport.Clone()
	transport.MaxConnsPerHost = 1
	transport.DisableCompression = true
	client := &http.Client{Transport: transport, Timeout: config.OperationTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidScanProtocol }}
	return &RemoteMalwareChecker{config: config, client: client, base: config.BaseURL}, nil
}

func (c *RemoteMalwareChecker) CheckSupport(ctx context.Context, _ artifact.Request) error {
	if c == nil || c.client == nil || c.config.Peer == nil || !c.config.Peer.Ready() {
		return artifact.ErrUnsupportedChecks
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/readyz", nil)
	if err != nil {
		return artifact.ErrUnsupportedChecks
	}
	response, err := c.client.Do(request)
	if err != nil {
		return errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent ||
		response.Header.Get("X-Sandbox-Rule-Set-Digest") != c.config.ExpectedRuleSetDigest {
		return artifact.ErrUnsupportedChecks
	}
	return ctx.Err()
}

func (c *RemoteMalwareChecker) CheckContent(ctx context.Context, request artifact.Request, content []byte) (artifact.CheckStatus, error) {
	if ctx == nil {
		return artifact.CheckNotRun, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return artifact.CheckNotRun, err
	}
	if c == nil || c.client == nil || c.config.Peer == nil || !c.config.Peer.Ready() ||
		len(content) == 0 || len(content) > artifact.MaxArtifactBytes ||
		scanDigest(content) != request.ExpectedDigest {
		return artifact.CheckNotRun, artifact.ErrUnsupportedChecks
	}
	authority, err := NewAuthority(ctx, request, c.config.ProfileDigest, c.config.Clock().UTC(), c.config.OperationTimeout)
	if err != nil {
		return artifact.CheckNotRun, errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	encoded, err := EncodeAuthority(authority)
	if err != nil {
		return artifact.CheckNotRun, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/scan", bytes.NewReader(content))
	if err != nil {
		return artifact.CheckNotRun, err
	}
	httpRequest.Header.Set("Content-Type", "application/octet-stream")
	httpRequest.Header.Set(scanAuthorityHeader, base64.RawURLEncoding.EncodeToString(encoded))
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return artifact.CheckNotRun, errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		return artifact.CheckNotRun, artifact.ErrUnsupportedChecks
	}
	encodedResponse, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(encodedResponse) > MaxResponseBytes {
		return artifact.CheckNotRun, errors.Join(artifact.ErrUnsupportedChecks, err)
	}
	result, err := DecodeResponse(encodedResponse, authority, c.config.Clock().UTC())
	if err != nil || result.RuleSetDigest != c.config.ExpectedRuleSetDigest || result.Active != artifact.CheckPassed {
		return artifact.CheckNotRun, artifact.ErrUnsupportedChecks
	}
	return result.Malware, ctx.Err()
}

func (c *RemoteMalwareChecker) Close() error {
	if c != nil && c.client != nil {
		c.client.CloseIdleConnections()
	}
	return nil
}

var _ artifact.ContentChecker = (*RemoteMalwareChecker)(nil)
var _ artifact.SupportChecker = (*RemoteMalwareChecker)(nil)

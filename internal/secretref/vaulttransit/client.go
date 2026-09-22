// Package vaulttransit implements the opaque envelope-key port with the Vault
// Transit HTTP API. It never reads or exports the Transit key itself.
package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	maxTokenBytes    = 8 << 10
	maxResponseBytes = 256 << 10
)

var componentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Config struct {
	Endpoint           string
	Mount              string
	ReferenceAuthority string
	OperationTimeout   time.Duration
	Now                func() time.Time
}

type Client struct {
	endpoint           string
	mount              string
	referenceAuthority string
	httpClient         *http.Client
	tokens             secretref.SecretProvider
	tokenBinding       secretref.Binding
	timeout            time.Duration
	now                func() time.Time
}

func New(config Config, httpClient *http.Client, tokens secretref.SecretProvider, tokenBinding secretref.Binding) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.String() != config.Endpoint {
		return nil, secretref.ErrUnavailable
	}
	if !componentPattern.MatchString(config.Mount) || !componentPattern.MatchString(config.ReferenceAuthority) || config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() || httpClient == nil || tokens == nil {
		return nil, secretref.ErrUnavailable
	}
	if tokenBinding.Validate() != nil || tokenBinding.Kind != secretref.KindSecret || tokenBinding.Purpose != secretref.PurposeWorkloadCredential || tokenBinding.Role != secretref.RoleProduct || tokenBinding.TenantID != secretref.SystemTenant {
		return nil, secretref.ErrUnavailable
	}
	clientCopy := *httpClient
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clientCopy.Timeout = 0
	return &Client{
		endpoint:           strings.TrimSuffix(config.Endpoint, "/"),
		mount:              config.Mount,
		referenceAuthority: config.ReferenceAuthority,
		httpClient:         &clientCopy,
		tokens:             tokens,
		tokenBinding:       tokenBinding,
		timeout:            config.OperationTimeout,
		now:                config.Now,
	}, nil
}

func (c *Client) SealEnvelope(ctx context.Context, binding secretref.Binding, plaintext, associatedData []byte) (secretref.OpaqueEnvelope, error) {
	if c == nil || ctx == nil || len(plaintext) > secretref.MaxPlaintextBytes || len(associatedData) < 1 || len(associatedData) > secretref.MaxAssociatedDataBytes {
		return secretref.OpaqueEnvelope{}, secretref.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return secretref.OpaqueEnvelope{}, err
	}
	keyVersion, err := c.validateBinding(binding)
	if err != nil {
		return secretref.OpaqueEnvelope{}, err
	}
	body, err := json.Marshal(encryptRequest{
		Plaintext:      plaintext,
		AssociatedData: associatedData,
		KeyVersion:     keyVersion,
	})
	if err != nil {
		return secretref.OpaqueEnvelope{}, secretref.ErrUnavailable
	}
	defer clear(body)
	response, err := c.request(ctx, "encrypt", binding.KeyID, body)
	if err != nil {
		return secretref.OpaqueEnvelope{}, err
	}
	defer clear(response)
	var data encryptResponse
	if decodeVaultData(response, &data) != nil || !validCiphertext(data.Ciphertext, binding.Version) {
		return secretref.OpaqueEnvelope{}, secretref.ErrUnavailable
	}
	return secretref.OpaqueEnvelope{
		BindingDigest: binding.Digest(),
		KeyID:         binding.KeyID,
		KeyVersion:    binding.Version,
		Algorithm:     secretref.EnvelopeAlgorithmV1,
		Ciphertext:    []byte(data.Ciphertext),
	}, nil
}

func (c *Client) OpenEnvelope(ctx context.Context, binding secretref.Binding, envelope secretref.OpaqueEnvelope, associatedData []byte) ([]byte, error) {
	if c == nil || ctx == nil || envelope.Validate(binding) != nil || len(associatedData) < 1 || len(associatedData) > secretref.MaxAssociatedDataBytes || !validCiphertext(string(envelope.Ciphertext), binding.Version) {
		return nil, secretref.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := c.validateBinding(binding); err != nil {
		return nil, err
	}
	body, err := json.Marshal(decryptRequest{
		Ciphertext:     string(envelope.Ciphertext),
		AssociatedData: associatedData,
	})
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	defer clear(body)
	response, err := c.request(ctx, "decrypt", binding.KeyID, body)
	if err != nil {
		return nil, err
	}
	defer clear(response)
	var data decryptResponse
	if decodeVaultData(response, &data) != nil || len(data.Plaintext) > secretref.MaxPlaintextBytes {
		clear(data.Plaintext)
		return nil, secretref.ErrUnavailable
	}
	return data.Plaintext, nil
}

func (c *Client) validateBinding(binding secretref.Binding) (int, error) {
	if binding.Validate() != nil || binding.Kind != secretref.KindEnvelopeKey || binding.KeyID == "" || binding.Purpose != secretref.PurposeRecordingEnvelopeKey || binding.Role != secretref.RoleProduct {
		return 0, secretref.ErrUnavailable
	}
	wantReference := "kms://" + c.referenceAuthority + "/" + c.mount + "/" + binding.KeyID
	if binding.Reference.String() != wantReference || len(binding.Version) < 2 || binding.Version[0] != 'v' {
		return 0, secretref.ErrUnavailable
	}
	version, err := strconv.Atoi(strings.TrimPrefix(binding.Version, "v"))
	if err != nil || version < 1 || strconv.Itoa(version) != strings.TrimPrefix(binding.Version, "v") {
		return 0, secretref.ErrUnavailable
	}
	return version, nil
}

func (c *Client) request(ctx context.Context, operation, keyID string, body []byte) ([]byte, error) {
	operationContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	material, err := c.tokens.ResolveSecret(operationContext, c.tokenBinding)
	if err != nil {
		material.Destroy()
		return nil, providerError(err)
	}
	defer material.Destroy()
	if material.Binding != c.tokenBinding || material.Validate(c.now()) != nil || !validToken(material.Bytes) {
		return nil, secretref.ErrUnavailable
	}
	requestURL := c.endpoint + "/v1/" + c.mount + "/" + operation + "/" + keyID
	request, err := http.NewRequestWithContext(operationContext, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", string(material.Bytes))
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, providerError(err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(responseBody) < 1 || len(responseBody) > maxResponseBytes || response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		clear(responseBody)
		return nil, secretref.ErrUnavailable
	}
	return responseBody, nil
}

func validToken(token []byte) bool {
	if len(token) < 1 || len(token) > maxTokenBytes {
		return false
	}
	for _, value := range token {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func validCiphertext(ciphertext, version string) bool {
	if len(ciphertext) < len("vault:v1:x") || len(ciphertext) > secretref.MaxEnvelopeBytes || !strings.HasPrefix(ciphertext, "vault:"+version+":") {
		return false
	}
	payload := strings.TrimPrefix(ciphertext, "vault:"+version+":")
	if payload == "" || strings.TrimSpace(payload) != payload {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(payload)
	return err == nil
}

func providerError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, secretref.ErrRevoked):
		return secretref.ErrRevoked
	case errors.Is(err, secretref.ErrExpired):
		return secretref.ErrExpired
	default:
		return secretref.ErrUnavailable
	}
}

var _ secretref.EnvelopeKeyProvider = (*Client)(nil)

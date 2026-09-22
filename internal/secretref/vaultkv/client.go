// Package vaultkv implements scoped SecretProvider resolution with the Vault
// KV v2 HTTP API. It is intended for the operator-owned workload-material
// agent, not direct use by Product/Provider/data-plane role processes.
package vaultkv

import (
	"context"
	"errors"
	"io"
	"mime"
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
	maxResponseBytes = 2 << 20
)

var componentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Config struct {
	Endpoint           string
	Mount              string
	ReferenceAuthority string
	Role               secretref.Role
	AllowedPurposes    []secretref.Purpose
	OperationTimeout   time.Duration
	Now                func() time.Time
}

type Client struct {
	endpoint           string
	mount              string
	referenceAuthority string
	role               secretref.Role
	allowed            map[secretref.Purpose]struct{}
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
	if !componentPattern.MatchString(config.Mount) || !componentPattern.MatchString(config.ReferenceAuthority) || !validRole(config.Role) ||
		len(config.AllowedPurposes) < 1 || config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute ||
		config.Now == nil || config.Now().IsZero() || httpClient == nil || tokens == nil {
		return nil, secretref.ErrUnavailable
	}
	if tokenBinding.Validate() != nil || tokenBinding.Kind != secretref.KindSecret || tokenBinding.Purpose != secretref.PurposeWorkloadCredential || tokenBinding.Role != config.Role || tokenBinding.TenantID != secretref.SystemTenant {
		return nil, secretref.ErrUnavailable
	}
	allowed := make(map[secretref.Purpose]struct{}, len(config.AllowedPurposes))
	for _, purpose := range config.AllowedPurposes {
		if !validPurpose(purpose) {
			return nil, secretref.ErrUnavailable
		}
		if _, duplicate := allowed[purpose]; duplicate {
			return nil, secretref.ErrUnavailable
		}
		allowed[purpose] = struct{}{}
	}
	clientCopy := *httpClient
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clientCopy.Timeout = 0
	return &Client{
		endpoint: strings.TrimSuffix(config.Endpoint, "/"), mount: config.Mount, referenceAuthority: config.ReferenceAuthority,
		role: config.Role, allowed: allowed, httpClient: &clientCopy, tokens: tokens, tokenBinding: tokenBinding,
		timeout: config.OperationTimeout, now: config.Now,
	}, nil
}

func (c *Client) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if c == nil || ctx == nil || binding.Validate() != nil || binding.Kind != secretref.KindSecret || binding.Role != c.role {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if _, allowed := c.allowed[binding.Purpose]; !allowed {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return secretref.SecretMaterial{}, err
	}
	version, path, err := c.bindingLocation(binding)
	if err != nil {
		return secretref.SecretMaterial{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	token, err := c.tokens.ResolveSecret(operationContext, c.tokenBinding)
	if err != nil {
		token.Destroy()
		return secretref.SecretMaterial{}, providerError(err)
	}
	defer token.Destroy()
	if token.Binding != c.tokenBinding || token.Validate(c.now()) != nil || !validToken(token.Bytes) {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	target := c.endpoint + "/v1/" + c.mount + "/data/" + path + "?version=" + strconv.Itoa(version)
	request, err := http.NewRequestWithContext(operationContext, http.MethodGet, target, nil)
	if err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", string(token.Bytes))
	response, err := c.httpClient.Do(request)
	if err != nil {
		return secretref.SecretMaterial{}, providerError(err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(responseBody) < 1 || len(responseBody) > maxResponseBytes || response.StatusCode != http.StatusOK ||
		!validJSONContentType(response.Header.Get("Content-Type")) {
		clear(responseBody)
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	defer clear(responseBody)
	material, err := decodeMaterial(responseBody, binding, version, c.now())
	if err != nil {
		material.Destroy()
		return secretref.SecretMaterial{}, err
	}
	return material, nil
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		return false
	}
	if len(parameters) == 0 {
		return true
	}
	charset, ok := parameters["charset"]
	return ok && len(parameters) == 1 && strings.EqualFold(charset, "utf-8")
}

func (c *Client) bindingLocation(binding secretref.Binding) (int, string, error) {
	parsed, err := url.Parse(binding.Reference.String())
	if err != nil || parsed.Scheme != "secret" || parsed.Host != c.referenceAuthority || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return 0, "", secretref.ErrUnavailable
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(segments) < 2 || len(segments) > 4 || segments[0] != c.mount {
		return 0, "", secretref.ErrUnavailable
	}
	for _, segment := range segments {
		if !componentPattern.MatchString(segment) {
			return 0, "", secretref.ErrUnavailable
		}
	}
	if len(binding.Version) < 2 || binding.Version[0] != 'v' {
		return 0, "", secretref.ErrUnavailable
	}
	version, err := strconv.Atoi(strings.TrimPrefix(binding.Version, "v"))
	if err != nil || version < 1 || strconv.Itoa(version) != strings.TrimPrefix(binding.Version, "v") {
		return 0, "", secretref.ErrUnavailable
	}
	return version, strings.Join(segments[1:], "/"), nil
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

func validRole(role secretref.Role) bool {
	switch role {
	case secretref.RoleProduct, secretref.RoleProvider, secretref.RoleGateway, secretref.RoleGuest, secretref.RoleBrowser, secretref.RoleDesktop:
		return true
	default:
		return false
	}
}

func validPurpose(purpose secretref.Purpose) bool {
	probe := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://probe/value", Version: "v1", Purpose: purpose, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct}
	return probe.Validate() == nil
}

var _ secretref.SecretProvider = (*Client)(nil)

package workloadcredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxVaultTokenBytes    = 8 << 10
	maxVaultResponseBytes = 256 << 10
)

type VaultIssuerConfig struct {
	Endpoint         string
	BackendID        string
	Policies         map[string]string
	ManagementToken  []byte
	OperationTimeout time.Duration
	Now              func() time.Time
}

type VaultIssuer struct {
	endpoint        string
	backendID       string
	policies        map[string]string
	managementToken []byte
	client          *http.Client
	timeout         time.Duration
	now             func() time.Time
}

func NewVaultIssuer(config VaultIssuerConfig, client *http.Client) (*VaultIssuer, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") ||
		endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.String() != config.Endpoint ||
		!identifierPattern.MatchString(config.BackendID) || len(config.Policies) < 1 || len(config.Policies) > maxPolicies ||
		!validVaultToken(config.ManagementToken) || config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute ||
		config.Now == nil || config.Now().IsZero() || client == nil {
		return nil, ErrUnavailable
	}
	policies := make(map[string]string, len(config.Policies))
	for policyID, vaultPolicy := range config.Policies {
		if !identifierPattern.MatchString(policyID) || !identifierPattern.MatchString(vaultPolicy) {
			return nil, ErrUnavailable
		}
		policies[policyID] = vaultPolicy
	}
	clientCopy := *client
	clientCopy.Jar = nil
	clientCopy.Timeout = 0
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &VaultIssuer{endpoint: strings.TrimSuffix(config.Endpoint, "/"), backendID: config.BackendID, policies: policies,
		managementToken: append([]byte(nil), config.ManagementToken...), client: &clientCopy, timeout: config.OperationTimeout, now: config.Now}, nil
}

func (v *VaultIssuer) Close() {
	if v != nil {
		clear(v.managementToken)
	}
}

func (v *VaultIssuer) Issue(ctx context.Context, spec IssueSpec) (IssuedCredential, error) {
	if v == nil || ctx == nil || spec.BackendID != v.backendID || !identifierPattern.MatchString(spec.LeaseID) ||
		spec.TTL < time.Second || spec.TTL > 15*time.Minute {
		return IssuedCredential{}, ErrUnavailable
	}
	policy, ok := v.policies[spec.PolicyID]
	if !ok {
		return IssuedCredential{}, ErrUnavailable
	}
	body, err := json.Marshal(struct {
		Policies        []string          `json:"policies"`
		TTL             string            `json:"ttl"`
		Renewable       bool              `json:"renewable"`
		NoDefaultPolicy bool              `json:"no_default_policy"`
		DisplayName     string            `json:"display_name"`
		Metadata        map[string]string `json:"meta"`
	}{Policies: []string{policy}, TTL: spec.TTL.String(), Renewable: false, NoDefaultPolicy: true, DisplayName: spec.LeaseID,
		Metadata: map[string]string{"agent_id": spec.AgentID, "policy_id": spec.PolicyID, "binding_digest": spec.BindingDigest}})
	if err != nil {
		return IssuedCredential{}, ErrUnavailable
	}
	defer clear(body)
	document, err := v.request(ctx, http.MethodPost, "/v1/auth/token/create", v.managementToken, body)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer clear(document)
	var response struct {
		RequestID     string          `json:"request_id"`
		LeaseID       string          `json:"lease_id"`
		Renewable     bool            `json:"renewable"`
		LeaseDuration int64           `json:"lease_duration"`
		Data          json.RawMessage `json:"data"`
		WrapInfo      json.RawMessage `json:"wrap_info"`
		Warnings      json.RawMessage `json:"warnings"`
		Auth          struct {
			ClientToken    string          `json:"client_token"`
			Accessor       string          `json:"accessor"`
			Policies       []string        `json:"policies"`
			TokenPolicies  []string        `json:"token_policies"`
			Metadata       json.RawMessage `json:"metadata"`
			LeaseDuration  int64           `json:"lease_duration"`
			Renewable      bool            `json:"renewable"`
			EntityID       string          `json:"entity_id"`
			TokenType      string          `json:"token_type"`
			Orphan         bool            `json:"orphan"`
			MFARequirement json.RawMessage `json:"mfa_requirement"`
			NumUses        int64           `json:"num_uses"`
		} `json:"auth"`
		MountType string `json:"mount_type"`
	}
	if decodeVaultResponse(document, &response) != nil || !validVaultToken([]byte(response.Auth.ClientToken)) ||
		!backendLeasePattern.MatchString(response.Auth.Accessor) || response.Auth.Renewable || response.Auth.LeaseDuration < 1 ||
		time.Duration(response.Auth.LeaseDuration)*time.Second > spec.TTL+time.Second || len(response.Auth.Policies) != 1 || response.Auth.Policies[0] != policy {
		return IssuedCredential{}, ErrUnavailable
	}
	return IssuedCredential{Credential: []byte(response.Auth.ClientToken), BackendLeaseID: response.Auth.Accessor,
		ExpiresAt: v.now().UTC().Add(time.Duration(response.Auth.LeaseDuration) * time.Second)}, nil
}

func (v *VaultIssuer) Verify(ctx context.Context, issued IssuedCredential) error {
	if v == nil || ctx == nil || !validVaultToken(issued.Credential) || !backendLeasePattern.MatchString(issued.BackendLeaseID) || !issued.ExpiresAt.After(v.now().UTC()) {
		return ErrUnavailable
	}
	body, err := json.Marshal(struct {
		Accessor string `json:"accessor"`
	}{Accessor: issued.BackendLeaseID})
	if err != nil {
		return ErrUnavailable
	}
	defer clear(body)
	document, err := v.request(ctx, http.MethodPost, "/v1/auth/token/lookup-accessor", v.managementToken, body)
	if err != nil {
		return err
	}
	defer clear(document)
	var response struct {
		RequestID     string `json:"request_id"`
		LeaseID       string `json:"lease_id"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int64  `json:"lease_duration"`
		Data          struct {
			Accessor       string          `json:"accessor"`
			CreationTime   int64           `json:"creation_time"`
			CreationTTL    int64           `json:"creation_ttl"`
			DisplayName    string          `json:"display_name"`
			EntityID       string          `json:"entity_id"`
			ExpireTime     json.RawMessage `json:"expire_time"`
			ExplicitMaxTTL int64           `json:"explicit_max_ttl"`
			ID             string          `json:"id"`
			IssueTime      json.RawMessage `json:"issue_time"`
			Meta           json.RawMessage `json:"meta"`
			NumUses        int64           `json:"num_uses"`
			Orphan         bool            `json:"orphan"`
			Path           string          `json:"path"`
			Policies       []string        `json:"policies"`
			Renewable      bool            `json:"renewable"`
			TTL            int64           `json:"ttl"`
			Type           string          `json:"type"`
		} `json:"data"`
		WrapInfo  json.RawMessage `json:"wrap_info"`
		Warnings  json.RawMessage `json:"warnings"`
		Auth      json.RawMessage `json:"auth"`
		MountType string          `json:"mount_type"`
	}
	if decodeVaultResponse(document, &response) != nil || response.Data.Accessor != issued.BackendLeaseID || response.Data.TTL < 1 {
		return ErrUnavailable
	}
	return nil
}

func (v *VaultIssuer) Revoke(ctx context.Context, backendLeaseID string) error {
	if v == nil || ctx == nil || !backendLeasePattern.MatchString(backendLeaseID) {
		return ErrUnavailable
	}
	body, err := json.Marshal(struct {
		Accessor string `json:"accessor"`
	}{Accessor: backendLeaseID})
	if err != nil {
		return ErrUnavailable
	}
	defer clear(body)
	_, err = v.request(ctx, http.MethodPost, "/v1/auth/token/revoke-accessor", v.managementToken, body)
	return err
}

func (v *VaultIssuer) request(ctx context.Context, method, path string, token, body []byte) ([]byte, error) {
	operationContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(operationContext, method, v.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", string(token))
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := v.client.Do(request)
	if err != nil {
		return nil, normalizeIssuerError(err)
	}
	defer response.Body.Close()
	document, readErr := io.ReadAll(io.LimitReader(response.Body, maxVaultResponseBytes+1))
	if readErr != nil || len(document) > maxVaultResponseBytes || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent) ||
		(response.StatusCode == http.StatusOK && (len(document) < 1 || !validJSONContentType(response.Header.Get("Content-Type")))) ||
		(response.StatusCode == http.StatusNoContent && len(document) != 0) {
		clear(document)
		return nil, ErrUnavailable
	}
	return document, nil
}

func decodeVaultResponse(document []byte, target any) error {
	if len(document) < 1 || len(document) > maxVaultResponseBytes || rejectDuplicateJSON(document) != nil {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
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
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrUnavailable
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrUnavailable
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrUnavailable
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrUnavailable
		}
	default:
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

var _ Issuer = (*VaultIssuer)(nil)

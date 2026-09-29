package workloadcredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
)

const (
	maxVaultTokenBytes    = 8 << 10
	maxVaultResponseBytes = 256 << 10
)

type VaultIssuerConfig struct {
	Endpoint                string
	BackendID               string
	Policies                map[string]string
	ManagementToken         []byte
	OperationTimeout        time.Duration
	Now                     func() time.Time
	RequireScopedTokenRoles bool
}

type VaultIssuer struct {
	endpoint         string
	backendID        string
	policies         map[string]string
	managementToken  []byte
	client           *http.Client
	timeout          time.Duration
	now              func() time.Time
	scopedTokenRoles bool
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
		managementToken: append([]byte(nil), config.ManagementToken...), client: &clientCopy, timeout: config.OperationTimeout,
		now: config.Now, scopedTokenRoles: config.RequireScopedTokenRoles}, nil
}

// Phase6TokenRole derives one fixed Vault role for one exact backend policy.
// Neither a workload request nor the controller JSON can select an API path.
func Phase6TokenRole(backendPolicy string) string {
	if !identifierPattern.MatchString(backendPolicy) {
		return ""
	}
	digest := sha256.Sum256([]byte("sandbox-runtime/phase6-vault-token-role/v1\x00" + backendPolicy))
	return "phase6-credential-" + hex.EncodeToString(digest[:20])
}

func equalVaultMetadata(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func isNullVaultJSON(value json.RawMessage) bool {
	return len(value) == 0 || bytes.Equal(value, []byte("null"))
}

func (v *VaultIssuer) Close() {
	if v != nil {
		clear(v.managementToken)
	}
}

// ValidateScopedRoles fails closed unless Vault exposes the exact operator-
// configured role restriction for every policy used by this v2 controller.
// The management token needs read access only to those fixed role paths.
func (v *VaultIssuer) ValidateScopedRoles(ctx context.Context) error {
	if v == nil || ctx == nil || !v.scopedTokenRoles {
		return ErrUnavailable
	}
	seen := make(map[string]struct{}, len(v.policies))
	for _, policy := range v.policies {
		if _, duplicate := seen[policy]; duplicate {
			continue
		}
		seen[policy] = struct{}{}
		role := Phase6TokenRole(policy)
		if role == "" {
			return ErrUnavailable
		}
		document, err := v.request(ctx, http.MethodGet, "/v1/auth/token/roles/"+role, v.managementToken, nil)
		if err != nil {
			return err
		}
		var response struct {
			RequestID     string `json:"request_id"`
			LeaseID       string `json:"lease_id"`
			Renewable     bool   `json:"renewable"`
			LeaseDuration int64  `json:"lease_duration"`
			Data          struct {
				AllowedEntityAliases   []string `json:"allowed_entity_aliases"`
				AllowedPolicies        []string `json:"allowed_policies"`
				AllowedPoliciesGlob    []string `json:"allowed_policies_glob"`
				DisallowedPolicies     []string `json:"disallowed_policies"`
				DisallowedPoliciesGlob []string `json:"disallowed_policies_glob"`
				ExplicitMaxTTL         int64    `json:"explicit_max_ttl"`
				Name                   string   `json:"name"`
				Orphan                 bool     `json:"orphan"`
				PathSuffix             string   `json:"path_suffix"`
				Period                 int64    `json:"period"`
				Renewable              bool     `json:"renewable"`
				TokenExplicitMaxTTL    int64    `json:"token_explicit_max_ttl"`
				TokenNoDefaultPolicy   bool     `json:"token_no_default_policy"`
				TokenPeriod            int64    `json:"token_period"`
				TokenType              string   `json:"token_type"`
			} `json:"data"`
			WrapInfo  json.RawMessage `json:"wrap_info"`
			Warnings  json.RawMessage `json:"warnings"`
			Auth      json.RawMessage `json:"auth"`
			MountType string          `json:"mount_type"`
		}
		decodeErr := decodeVaultResponse(document, &response)
		clear(document)
		data := response.Data
		if decodeErr != nil || data.Name != role || len(data.AllowedPolicies) != 1 || data.AllowedPolicies[0] != policy ||
			len(data.AllowedPoliciesGlob) != 0 || len(data.DisallowedPolicies) != 2 ||
			!((data.DisallowedPolicies[0] == "default" && data.DisallowedPolicies[1] == "root") ||
				(data.DisallowedPolicies[0] == "root" && data.DisallowedPolicies[1] == "default")) ||
			len(data.DisallowedPoliciesGlob) != 0 || len(data.AllowedEntityAliases) != 0 ||
			!data.TokenNoDefaultPolicy || data.TokenType != "service" || data.Orphan || data.Renewable ||
			data.TokenExplicitMaxTTL != int64((15*time.Minute)/time.Second) || data.ExplicitMaxTTL != 0 ||
			data.Period != 0 || data.TokenPeriod != 0 || data.PathSuffix != "" || !isNullVaultJSON(response.Warnings) {
			return ErrUnavailable
		}
	}
	return nil
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
	backendSpec := credentialbackend.IssueSpec{SubjectID: spec.AgentID, SubjectDigest: spec.BindingDigest, PolicyID: spec.PolicyID,
		Purpose:      string(spec.Purpose),
		PolicyDigest: spec.BindingDigest, BindingDigest: spec.BindingDigest, BackendID: spec.BackendID, BackendPolicy: policy, LeaseID: spec.LeaseID, TTL: spec.TTL}
	return v.issueWithMetadata(ctx, backendSpec, map[string]string{"agent_id": spec.AgentID, "policy_id": spec.PolicyID, "binding_digest": spec.BindingDigest})
}

func (v *VaultIssuer) IssueScoped(ctx context.Context, spec credentialbackend.IssueSpec) (credentialbackend.IssuedCredential, error) {
	if v == nil || ctx == nil || spec.BackendID != v.backendID || !identifierPattern.MatchString(spec.SubjectID) || !validDigest(spec.SubjectDigest) ||
		!identifierPattern.MatchString(spec.PolicyID) || !validDigest(spec.PolicyDigest) || !validDigest(spec.BindingDigest) ||
		!identifierPattern.MatchString(spec.BackendPolicy) || !identifierPattern.MatchString(spec.LeaseID) || spec.TTL < time.Second || spec.TTL > 15*time.Minute {
		return credentialbackend.IssuedCredential{}, ErrUnavailable
	}
	policy, ok := v.policies[spec.PolicyID]
	if !ok || policy != spec.BackendPolicy {
		return credentialbackend.IssuedCredential{}, ErrUnavailable
	}
	return v.issueWithMetadata(ctx, spec, map[string]string{"subject_id": spec.SubjectID, "subject_digest": spec.SubjectDigest,
		"policy_id": spec.PolicyID, "policy_digest": spec.PolicyDigest, "binding_digest": spec.BindingDigest,
		"purpose": spec.Purpose, "lease_id": spec.LeaseID})
}

func (v *VaultIssuer) issueWithMetadata(ctx context.Context, spec credentialbackend.IssueSpec, metadata map[string]string) (credentialbackend.IssuedCredential, error) {
	path, role := "/v1/auth/token/create", ""
	if v.scopedTokenRoles {
		role = Phase6TokenRole(spec.BackendPolicy)
		if role == "" || spec.Purpose == "" || metadata["subject_id"] != spec.SubjectID || metadata["subject_digest"] != spec.SubjectDigest ||
			metadata["policy_id"] != spec.PolicyID || metadata["policy_digest"] != spec.PolicyDigest ||
			metadata["binding_digest"] != spec.BindingDigest || metadata["purpose"] != spec.Purpose ||
			metadata["lease_id"] != spec.LeaseID || len(metadata) != 7 {
			return credentialbackend.IssuedCredential{}, ErrUnavailable
		}
		path += "/" + role
	}
	body, err := json.Marshal(struct {
		Policies        []string          `json:"policies"`
		TTL             string            `json:"ttl"`
		Renewable       bool              `json:"renewable"`
		NoDefaultPolicy bool              `json:"no_default_policy"`
		DisplayName     string            `json:"display_name"`
		Metadata        map[string]string `json:"meta"`
	}{Policies: []string{spec.BackendPolicy}, TTL: spec.TTL.String(), Renewable: false, NoDefaultPolicy: true, DisplayName: spec.LeaseID,
		Metadata: metadata})
	if err != nil {
		return IssuedCredential{}, ErrUnavailable
	}
	defer clear(body)
	document, err := v.request(ctx, http.MethodPost, path, v.managementToken, body)
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
		response.Auth.LeaseDuration > int64(spec.TTL/time.Second)+1 || len(response.Auth.Policies) != 1 || response.Auth.Policies[0] != spec.BackendPolicy {
		return IssuedCredential{}, ErrUnavailable
	}
	if v.scopedTokenRoles {
		var actualMetadata map[string]string
		if json.Unmarshal(response.Auth.Metadata, &actualMetadata) != nil || !equalVaultMetadata(actualMetadata, metadata) ||
			len(response.Auth.TokenPolicies) != 1 || response.Auth.TokenPolicies[0] != spec.BackendPolicy ||
			response.Auth.Orphan || response.Auth.TokenType != "service" || response.Auth.NumUses != 0 ||
			!isNullVaultJSON(response.Warnings) {
			return IssuedCredential{}, ErrUnavailable
		}
	}
	return IssuedCredential{Credential: []byte(response.Auth.ClientToken), BackendLeaseID: response.Auth.Accessor,
		ExpiresAt: v.now().UTC().Add(time.Duration(response.Auth.LeaseDuration) * time.Second),
		PolicyID:  spec.PolicyID, PolicyDigest: spec.PolicyDigest, SubjectID: spec.SubjectID,
		SubjectDigest: spec.SubjectDigest, BindingDigest: spec.BindingDigest,
		BackendPolicy: spec.BackendPolicy, TokenRole: role, RequestedTTL: spec.TTL,
		Purpose: spec.Purpose, LeaseID: spec.LeaseID}, nil
}

func (v *VaultIssuer) Verify(ctx context.Context, issued IssuedCredential) error {
	if v == nil || ctx == nil || !validVaultToken(issued.Credential) || !backendLeasePattern.MatchString(issued.BackendLeaseID) || !issued.ExpiresAt.After(v.now().UTC()) {
		return ErrUnavailable
	}
	if v.scopedTokenRoles {
		backendPolicy, allowed := v.policies[issued.PolicyID]
		if !allowed || backendPolicy != issued.BackendPolicy || issued.TokenRole == "" ||
			issued.TokenRole != Phase6TokenRole(backendPolicy) || !identifierPattern.MatchString(issued.LeaseID) ||
			issued.Purpose == "" || issued.RequestedTTL < time.Second || issued.RequestedTTL > 15*time.Minute ||
			!identifierPattern.MatchString(issued.SubjectID) || !validDigest(issued.PolicyDigest) ||
			!validDigest(issued.SubjectDigest) || !validDigest(issued.BindingDigest) {
			return ErrUnavailable
		}
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
			Role           string          `json:"role"`
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
	if v.scopedTokenRoles {
		expectedMetadata := map[string]string{"subject_id": issued.SubjectID, "subject_digest": issued.SubjectDigest,
			"policy_id": issued.PolicyID, "policy_digest": issued.PolicyDigest,
			"binding_digest": issued.BindingDigest, "purpose": issued.Purpose, "lease_id": issued.LeaseID}
		var actualMetadata map[string]string
		if json.Unmarshal(response.Data.Meta, &actualMetadata) != nil ||
			!equalVaultMetadata(actualMetadata, expectedMetadata) ||
			response.Data.Path != "auth/token/create/"+issued.TokenRole ||
			response.Data.Role != issued.TokenRole ||
			len(response.Data.Policies) != 1 || response.Data.Policies[0] != issued.BackendPolicy ||
			response.Data.Orphan || response.Data.Renewable || response.Data.Type != "service" ||
			response.Data.NumUses != 0 || response.Data.CreationTTL < 1 ||
			response.Data.CreationTTL > int64(issued.RequestedTTL/time.Second)+1 ||
			response.Data.TTL > int64(issued.RequestedTTL/time.Second)+1 ||
			!isNullVaultJSON(response.Warnings) {
			return ErrUnavailable
		}
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

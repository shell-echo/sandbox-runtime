package productgateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

const (
	browserBindingDomain        = "sandbox-runtime/browser-handoff-tenant-binding/v2"
	maxBrowserBindingGeneration = int64(9_007_199_254_740_991)
)

var (
	errBrowserBindingInput   = errors.New("invalid Browser tenant binding input")
	browserBindingIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	browserBindingReference  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
)

// BrowserTenantBindingInput is the closed, exact-handoff projection of a
// committed Product binding and validated caller/Provider configuration.
// One-use grants, capacity claims, control leases, expiry and connection
// epochs deliberately are not fields of this stable resource identity.
type BrowserTenantBindingInput struct {
	CallerAuthorityScope     string `json:"caller_authority_scope"`
	ProviderInstanceAudience string `json:"provider_instance_audience"`
	TenantID                 string `json:"tenant_id"`
	SandboxID                string `json:"sandbox_id"`
	BrowserSessionID         string `json:"browser_session_id"`
	ProviderRevisionID       string `json:"provider_revision_id"`
	CapabilityProfileID      string `json:"capability_profile_id"`
	ConnectionGeneration     int64  `json:"connection_generation"`
	HandoffReference         string `json:"handoff_reference"`
}

func (i BrowserTenantBindingInput) Validate() error {
	for _, value := range []string{i.CallerAuthorityScope, i.ProviderInstanceAudience, i.TenantID,
		i.SandboxID, i.BrowserSessionID, i.ProviderRevisionID} {
		if !browserBindingIdentifier.MatchString(value) {
			return errBrowserBindingInput
		}
	}
	if i.CapabilityProfileID != "browser-v1" || i.ConnectionGeneration < 1 ||
		i.ConnectionGeneration > maxBrowserBindingGeneration || !browserBindingReference.MatchString(i.HandoffReference) {
		return errBrowserBindingInput
	}
	return nil
}

// DeriveBrowserTenantBinding uses a dedicated 32-byte Product/Gateway key.
// Its output is privacy-preserving consistency evidence, not a grant token.
// The caller must select the key version fixed with the Product handoff
// metadata; this helper never falls back to an active/default key.
func DeriveBrowserTenantBinding(key []byte, input BrowserTenantBindingInput) (string, error) {
	if len(key) != sha256.Size || input.Validate() != nil {
		return "", errBrowserBindingInput
	}
	document, err := json.Marshal(input)
	if err != nil {
		return "", errBrowserBindingInput
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(browserBindingDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(document)
	return "hmac-sha256:v2:" + hex.EncodeToString(mac.Sum(nil)), nil
}

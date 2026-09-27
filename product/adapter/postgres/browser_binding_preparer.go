package productpostgres

import (
	"context"

	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
)

// BrowserHandoffKeySelection is fixed by the validated Product/Provider
// instance configuration. Rotation creates a new preparer for new handoffs;
// it does not alter an already-committed metadata row.
type BrowserHandoffKeySelection struct {
	CallerAuthorityScope     string
	ProviderInstanceAudience string
	ActiveVersion            string
	BindingIDsByVersion      map[string]string
}

type browserHandoffKeyPreparer struct {
	scope     string
	audience  string
	version   string
	bindingID string
	keyring   *productgateway.BrowserBindingKeyring
}

func NewBrowserHandoffKeyPreparer(source productgateway.BrowserBindingKeySource, config BrowserHandoffKeySelection) (BrowserHandoffBindingPreparer, error) {
	keyring, err := productgateway.NewBrowserBindingKeyring(source, config.BindingIDsByVersion)
	bindingID, selected := config.BindingIDsByVersion[config.ActiveVersion]
	if err != nil || !selected || !browserBindingKeyName.MatchString(bindingID) ||
		!browserBindingKeyVersion.MatchString(config.ActiveVersion) ||
		!browserBindingSessionID.MatchString(config.CallerAuthorityScope) ||
		!browserBindingSessionID.MatchString(config.ProviderInstanceAudience) {
		return nil, product.ErrInvalid
	}
	return &browserHandoffKeyPreparer{scope: config.CallerAuthorityScope,
		audience: config.ProviderInstanceAudience, version: config.ActiveVersion,
		bindingID: bindingID, keyring: keyring}, nil
}

func (p *browserHandoffKeyPreparer) PrepareBrowserHandoffBinding(ctx context.Context, work product.ProviderObservationWork, evidence product.ProviderOperationEvidence) (BrowserHandoffBindingSelection, error) {
	if p == nil || p.keyring == nil || ctx == nil || work.ProviderAction != "open_browser_session" ||
		(work.SessionKind != product.SessionKindBrowserAutomation && work.SessionKind != product.SessionKindBrowserLive) ||
		evidence.State != "succeeded" || evidence.ProviderRevisionID != work.ProviderRevisionID ||
		evidence.SandboxID != work.SandboxID {
		return BrowserHandoffBindingSelection{}, product.ErrInvalid
	}
	input := productgateway.BrowserTenantBindingInput{CallerAuthorityScope: p.scope,
		ProviderInstanceAudience: p.audience, TenantID: work.TenantID, SandboxID: work.SandboxID,
		BrowserSessionID: work.SessionID, ProviderRevisionID: work.ProviderRevisionID,
		CapabilityProfileID: "browser-v1", ConnectionGeneration: evidence.ConnectionGeneration,
		HandoffReference: evidence.HandoffReference}
	digest, keyBinding, err := p.keyring.DeriveWithBinding(ctx, p.version, input)
	if err != nil {
		return BrowserHandoffBindingSelection{}, product.ErrStoreUnavailable
	}
	selected := BrowserHandoffBindingSelection{ProductSessionID: work.SessionID, Input: input,
		KeyBindingID: p.bindingID, KeyVersion: p.version, KeyBinding: keyBinding,
		KeyBindingDigest: keyBinding.Digest(), TenantBindingDigest: digest,
		HandoffExpiresAt: evidence.HandoffExpiresAt}
	if selected.Validate() != nil {
		return BrowserHandoffBindingSelection{}, product.ErrInvalid
	}
	return selected, nil
}

var _ BrowserHandoffBindingPreparer = (*browserHandoffKeyPreparer)(nil)

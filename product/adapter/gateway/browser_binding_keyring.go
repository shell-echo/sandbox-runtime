package productgateway

import (
	"context"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const maxBrowserBindingKeyVersions = 32

var (
	browserBindingKeyVersion = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	browserBindingKeyID      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

// BrowserBindingKeySource is the existing role-private material registry
// projection. Neither Provider nor either executor receives this capability.
type BrowserBindingKeySource interface {
	Resolve(context.Context, string, secretref.Purpose, string) (secretref.SecretMaterial, error)
}

// BrowserBindingKeyring has no active/default key. The committed Product
// handoff metadata supplies the exact version for every derivation.
type BrowserBindingKeyring struct {
	source   BrowserBindingKeySource
	versions map[string]string
}

func NewBrowserBindingKeyring(source BrowserBindingKeySource, versions map[string]string) (*BrowserBindingKeyring, error) {
	if source == nil || len(versions) < 1 || len(versions) > maxBrowserBindingKeyVersions {
		return nil, errBrowserBindingInput
	}
	copyVersions := make(map[string]string, len(versions))
	usedIDs := make(map[string]struct{}, len(versions))
	for version, bindingID := range versions {
		if !browserBindingKeyVersion.MatchString(version) || !browserBindingKeyID.MatchString(bindingID) {
			return nil, errBrowserBindingInput
		}
		if _, used := usedIDs[bindingID]; used {
			return nil, errBrowserBindingInput
		}
		usedIDs[bindingID] = struct{}{}
		copyVersions[version] = bindingID
	}
	return &BrowserBindingKeyring{source: source, versions: copyVersions}, nil
}

func (k *BrowserBindingKeyring) Derive(ctx context.Context, committedVersion string, input BrowserTenantBindingInput) (string, error) {
	digest, _, err := k.DeriveWithBinding(ctx, committedVersion, input)
	return digest, err
}

// DeriveWithBinding returns the non-secret canonical source binding so
// Product can persist the exact reference/version/purpose selected first.
func (k *BrowserBindingKeyring) DeriveWithBinding(ctx context.Context, committedVersion string, input BrowserTenantBindingInput) (string, secretref.Binding, error) {
	if k == nil || k.source == nil || ctx == nil || input.Validate() != nil {
		return "", secretref.Binding{}, errBrowserBindingInput
	}
	if err := ctx.Err(); err != nil {
		return "", secretref.Binding{}, err
	}
	bindingID, selected := k.versions[committedVersion]
	if !selected {
		return "", secretref.Binding{}, errBrowserBindingInput
	}
	material, err := k.source.Resolve(ctx, bindingID, secretref.PurposeBrowserTenantBindingKey, secretref.SystemTenant)
	if err != nil {
		material.Destroy()
		return "", secretref.Binding{}, errBrowserBindingInput
	}
	defer material.Destroy()
	if material.Binding.Purpose != secretref.PurposeBrowserTenantBindingKey ||
		material.Binding.TenantID != secretref.SystemTenant ||
		(material.Binding.Role != secretref.RoleProduct && material.Binding.Role != secretref.RoleGateway) ||
		material.Binding.Version != committedVersion || material.Validate(time.Now().UTC()) != nil {
		return "", secretref.Binding{}, errBrowserBindingInput
	}
	if err := ctx.Err(); err != nil {
		return "", secretref.Binding{}, err
	}
	digest, err := DeriveBrowserTenantBinding(material.Bytes, input)
	if err != nil {
		return "", secretref.Binding{}, err
	}
	return digest, material.Binding, nil
}

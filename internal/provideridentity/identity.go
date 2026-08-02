// Package provideridentity defines the bounded URI identity policy shared by
// Provider configuration and transport admission.
package provideridentity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	// MaxAllowedIdentities bounds startup memory and certificate admission work.
	MaxAllowedIdentities = 32
	// MaxIdentityBytes bounds one exact URI identity in its wire representation.
	MaxIdentityBytes = 2048
)

// ValidateAllowlist rejects empty, oversized, malformed, and duplicate exact
// absolute URI identities.
func ValidateAllowlist(identities []string) error {
	if count := len(identities); count < 1 || count > MaxAllowedIdentities {
		return fmt.Errorf("allowed client URI identities count must be between 1 and %d, got %d", MaxAllowedIdentities, count)
	}
	seen := make(map[string]struct{}, len(identities))
	for index, identity := range identities {
		if err := ValidateExactAbsoluteURI(identity); err != nil {
			return fmt.Errorf("allowed client URI identity %d: %w", index, err)
		}
		if _, duplicate := seen[identity]; duplicate {
			return fmt.Errorf("duplicate allowed client URI identity %q", identity)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

// ValidateExactAbsoluteURI validates the exact string compared with a client
// certificate URI SAN. It deliberately performs no semantic normalization.
func ValidateExactAbsoluteURI(identity string) error {
	if !utf8.ValidString(identity) {
		return errors.New("must be valid UTF-8")
	}
	if size := len(identity); size < 1 || size > MaxIdentityBytes {
		return fmt.Errorf("must contain between 1 and %d bytes, got %d", MaxIdentityBytes, size)
	}
	if strings.TrimSpace(identity) != identity {
		return errors.New("must not contain surrounding whitespace")
	}
	parsed, err := url.Parse(identity)
	if err != nil {
		return fmt.Errorf("must be an absolute URI: %w", err)
	}
	if !parsed.IsAbs() || parsed.Scheme == "" || parsed.Fragment != "" || parsed.String() != identity {
		return errors.New("must be an exact absolute URI")
	}
	return nil
}

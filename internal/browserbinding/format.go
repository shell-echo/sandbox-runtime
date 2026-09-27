// Package browserbinding validates the private Browser v2 tenant/resource
// binding format. Derivation is deliberately owned by Product/Gateway, never
// by Provider or an executor.
package browserbinding

import (
	"errors"
	"regexp"
)

const Prefix = "hmac-sha256:v2:"

var (
	ErrInvalid = errors.New("invalid Browser v2 tenant binding digest")
	pattern    = regexp.MustCompile(`^hmac-sha256:v2:[0-9a-f]{64}$`)
)

func ValidateDigest(value string) error {
	if !pattern.MatchString(value) {
		return ErrInvalid
	}
	return nil
}

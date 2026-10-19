// Package controlbootstrap verifies a declared public bootstrap key against a
// separately provisioned executable commitment. A Profile or loader envelope
// can never choose that commitment. This does not verify an operator signature
// or authorize Store, service startup or dispatch.
package controlbootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrUnavailable = errors.New("Control operator bootstrap unavailable")

// publicKeyPin is a build/deployment trust root, not a CLI/env/Profile option.
// Normal builds deliberately leave it empty. A release must independently
// approve and attest the provisioning of this commitment.
var publicKeyPin string

// Credential can only be obtained by verifying the compiled pin and sealed FD3.
// No raw key, mutable review or caller-provided digest can create this capability.
type Credential struct {
	key      ed25519.PublicKey
	document []byte
}

func (c *Credential) Review() (phase6security.ControlBootstrapReview, error) {
	if c == nil || len(c.key) != ed25519.PublicKeySize {
		return phase6security.ControlBootstrapReview{}, ErrUnavailable
	}
	return phase6security.ReviewControlBootstrap(c.document)
}

// Document returns an owned snapshot of the already pin-authenticated Profile.
// It is descriptive input to a read-only source observer, not a Store permit.
func (c *Credential) Document() ([]byte, error) {
	if _, e := c.Review(); e != nil {
		return nil, e
	}
	return slices.Clone(c.document), nil
}
func (c *Credential) VerifySignature(message, signature []byte) bool {
	return c != nil && len(c.key) == ed25519.PublicKeySize && ed25519.Verify(c.key, message, signature)
}
func Verify(ctx context.Context, document []byte, fd *os.File) (phase6security.ControlBootstrapReview, error) {
	c, e := Open(ctx, document, fd)
	if e != nil {
		return phase6security.ControlBootstrapReview{}, e
	}
	return c.Review()
}
func Open(ctx context.Context, document []byte, fd *os.File) (*Credential, error) {
	if fd == nil {
		return nil, ErrUnavailable
	}
	defer fd.Close()
	if ctx == nil || ctx.Err() != nil || fd.Fd() != 3 || len(publicKeyPin) != 71 {
		return nil, ErrUnavailable
	}
	r, e := phase6security.ReviewControlBootstrap(document)
	if e != nil || r.Bootstrap.KeyDigest != publicKeyPin {
		return nil, ErrUnavailable
	}
	if (r.Bootstrap.Target == phase6security.ControlDeliveryTarget || phase6security.ControlObservesSource(r.Bootstrap.Target)) && os.Getpid() != 1 {
		return nil, ErrUnavailable
	}
	matched := false
	for _, s := range r.Services {
		if s.Launch.Target == r.Bootstrap.Target {
			groups, err := os.Getgroups()
			actual := make([]uint32, len(groups))
			for i, g := range groups {
				if g < 0 {
					return nil, ErrUnavailable
				}
				actual[i] = uint32(g)
			}
			slices.Sort(actual)
			if err != nil || os.Getuid() != int(s.Principal.UID) || os.Geteuid() != int(s.Principal.UID) || os.Getgid() != int(s.Principal.GID) || os.Getegid() != int(s.Principal.GID) || !slices.Equal(actual, s.Groups) {
				return nil, ErrUnavailable
			}
			matched = true
		}
	}
	if !matched {
		return nil, ErrUnavailable
	}
	key, e := readSealedKey(ctx, fd)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer clear(key)
	sum := sha256.Sum256(key)
	if "sha256:"+hex.EncodeToString(sum[:]) != publicKeyPin {
		return nil, ErrUnavailable
	}
	return &Credential{key: append(ed25519.PublicKey(nil), key...), document: append([]byte(nil), document...)}, nil
}

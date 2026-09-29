// Package credentialbackend defines the version-neutral backend boundary used
// by private workload credential protocols. Protocol identity and lease truth
// remain owned by their respective controllers.
package credentialbackend

import (
	"context"
	"time"
)

type IssueSpec struct {
	SubjectID     string
	SubjectDigest string
	Purpose       string
	PolicyID      string
	PolicyDigest  string
	BindingDigest string
	BackendID     string
	BackendPolicy string
	LeaseID       string
	TTL           time.Duration
}

type IssuedCredential struct {
	Credential     []byte
	BackendLeaseID string
	ExpiresAt      time.Time
	// Scoped token-role expectations are ephemeral issuer-to-verifier data.
	// They are never persisted in the controller ledger or exposed on the wire.
	PolicyID      string
	PolicyDigest  string
	SubjectID     string
	SubjectDigest string
	BindingDigest string
	BackendPolicy string
	TokenRole     string
	RequestedTTL  time.Duration
	Purpose       string
	LeaseID       string
}

func (c *IssuedCredential) Destroy() {
	if c != nil {
		clear(c.Credential)
		c.Credential = nil
	}
}

type Issuer interface {
	IssueScoped(context.Context, IssueSpec) (IssuedCredential, error)
	Verify(context.Context, IssuedCredential) error
	Revoke(context.Context, string) error
}

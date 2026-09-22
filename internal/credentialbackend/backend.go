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

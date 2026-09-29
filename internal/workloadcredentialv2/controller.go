package workloadcredentialv2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
)

const (
	LedgerSchema   = "sandbox-runtime.workload-credential-ledger.v2"
	maxPolicies    = 128
	maxLedgerItems = 8192

	leaseActive  = "active"
	leaseRevoked = "revoked"
	leaseExpired = "expired"
)

type ControllerConfig struct {
	LedgerPath string
	Policies   []Policy
	Issuer     credentialbackend.Issuer
	Overlap    time.Duration
	Now        func() time.Time
	Random     io.Reader
}

type Controller struct {
	mu         sync.Mutex
	ledgerPath string
	policies   map[string]Policy
	issuer     credentialbackend.Issuer
	overlap    time.Duration
	now        func() time.Time
	random     io.Reader
	ledger     Ledger
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Issuer == nil || config.Now == nil || config.Now().IsZero() || config.Random == nil ||
		config.Overlap < time.Second || config.Overlap > 30*time.Second || len(config.Policies) < 1 || len(config.Policies) > maxPolicies {
		return nil, ErrUnavailable
	}
	controller := &Controller{ledgerPath: config.LedgerPath, policies: make(map[string]Policy, len(config.Policies)), issuer: config.Issuer,
		overlap: config.Overlap, now: config.Now, random: config.Random}
	for _, policy := range config.Policies {
		if policy.Validate() != nil {
			return nil, ErrUnavailable
		}
		if _, duplicate := controller.policies[policy.ID]; duplicate {
			return nil, ErrUnavailable
		}
		policy.PublicKey = append([]byte(nil), policy.PublicKey...)
		controller.policies[policy.ID] = policy
	}
	ledger, err := loadLedger(config.LedgerPath)
	if err != nil {
		return nil, err
	}
	controller.ledger = ledger
	if controller.ledger.Schema == "" {
		controller.ledger = Ledger{Schema: LedgerSchema, Revision: 1}
		if err := saveLedger(config.LedgerPath, controller.ledger); err != nil {
			return nil, err
		}
	}
	if controller.validateLedger() != nil {
		return nil, ErrUnavailable
	}
	return controller, nil
}

func NewProductionController(config ControllerConfig) (*Controller, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return NewController(config)
}

func (c *Controller) Handle(ctx context.Context, request Request, peerUID, peerGID uint32) (Response, error) {
	if c == nil || ctx == nil {
		return Response{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	policy, ok := c.policies[request.PolicyID]
	if !ok || policy.ExpectedUID != peerUID || policy.ExpectedGID != peerGID || request.Validate(policy, now) != nil || !c.consumeReplay(request.JTI, now) {
		return errorResponse(request, StatusDenied), ErrDenied
	}
	if err := c.persist(); err != nil {
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	deadline, _ := parseTime(request.Deadline)
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	switch request.Type {
	case IssueType:
		return c.issue(operationContext, request, policy, now)
	case RenewType:
		return c.renew(operationContext, request, policy, now)
	case RevokeType:
		return c.revoke(operationContext, request, policy, now)
	case StatusType:
		return c.status(request, policy, now)
	default:
		return errorResponse(request, StatusDenied), ErrDenied
	}
}

func (c *Controller) issue(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	for _, lease := range c.ledger.Leases {
		if lease.PrincipalDigest == policy.Principal.Digest() && lease.PolicyDigest == policy.Digest() && lease.State == leaseActive && lease.ExpiresAt.After(now) {
			return errorResponse(request, StatusDenied), ErrDenied
		}
	}
	leaseID, err := c.newLeaseID()
	if err != nil {
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	ttl := min(time.Duration(request.RequestedTTL)*time.Second, policy.MaxTTL)
	issued, err := c.issuer.IssueScoped(ctx, issueSpec(policy, leaseID, ttl))
	if err != nil || validateIssued(issued, now, ttl) != nil || c.issuer.Verify(ctx, issued) != nil {
		issued.Destroy()
		if issued.BackendLeaseID != "" {
			_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		}
		return errorResponse(request, StatusUnavailable), normalizeIssuerError(err)
	}
	defer issued.Destroy()
	lease := ledgerLeaseFromIssued(policy, leaseID, issued, now, 1)
	c.ledger.Leases = append(c.ledger.Leases, lease)
	if err := c.persist(); err != nil {
		_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	return okResponse(request, lease, issued.Credential), nil
}

func (c *Controller) renew(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	index, lease := c.findLease(request.LeaseID)
	if lease == nil || !policy.Renewable || lease.State != leaseActive || lease.Revision != request.Revision || !lease.ExpiresAt.After(now) || !leaseMatchesPolicy(*lease, policy) {
		return errorResponse(request, StatusDenied), ErrDenied
	}
	ttl := min(time.Duration(request.RequestedTTL)*time.Second, policy.MaxTTL)
	issued, err := c.issuer.IssueScoped(ctx, issueSpec(policy, lease.LeaseID, ttl))
	if err != nil || validateIssued(issued, now, ttl) != nil || c.issuer.Verify(ctx, issued) != nil {
		issued.Destroy()
		if issued.BackendLeaseID != "" {
			_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		}
		return errorResponse(request, StatusUnavailable), normalizeIssuerError(err)
	}
	defer issued.Destroy()
	replacement := ledgerLeaseFromIssued(policy, lease.LeaseID, issued, now, lease.Revision+1)
	replacement.PreviousBackendLeaseID = lease.BackendLeaseID
	replacement.PreviousRevokeAt = now.Add(c.overlap)
	c.ledger.Leases[index] = replacement
	if err := c.persist(); err != nil {
		_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	return okResponse(request, replacement, issued.Credential), nil
}

func (c *Controller) revoke(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	index, lease := c.findLease(request.LeaseID)
	if lease == nil || lease.Revision != request.Revision || !leaseMatchesPolicy(*lease, policy) || lease.State != leaseActive {
		return errorResponse(request, StatusDenied), ErrDenied
	}
	if err := c.issuer.Revoke(ctx, lease.BackendLeaseID); err != nil {
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	if lease.PreviousBackendLeaseID != "" {
		if err := c.issuer.Revoke(ctx, lease.PreviousBackendLeaseID); err != nil {
			return errorResponse(request, StatusUnavailable), ErrUnavailable
		}
	}
	lease.State, lease.Revision, lease.RevokedAt = leaseRevoked, lease.Revision+1, now
	lease.PreviousBackendLeaseID, lease.PreviousRevokeAt = "", time.Time{}
	c.ledger.Leases[index] = *lease
	if err := c.persist(); err != nil {
		return errorResponse(request, StatusUnavailable), ErrUnavailable
	}
	return okResponse(request, *lease, nil), nil
}

func (c *Controller) status(request Request, policy Policy, now time.Time) (Response, error) {
	_, lease := c.findLease(request.LeaseID)
	if lease == nil || lease.Revision != request.Revision || !leaseMatchesPolicy(*lease, policy) {
		return errorResponse(request, StatusDenied), ErrDenied
	}
	if lease.State == leaseRevoked {
		return errorResponse(request, StatusRevoked), ErrRevoked
	}
	if !lease.ExpiresAt.After(now) {
		return errorResponse(request, StatusExpired), ErrExpired
	}
	return okResponse(request, *lease, nil), nil
}

func (c *Controller) Reap(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	changed := false
	for index := range c.ledger.Leases {
		lease := &c.ledger.Leases[index]
		if lease.PreviousBackendLeaseID != "" && !lease.PreviousRevokeAt.After(now) {
			if err := c.issuer.Revoke(ctx, lease.PreviousBackendLeaseID); err != nil {
				return ErrUnavailable
			}
			lease.PreviousBackendLeaseID, lease.PreviousRevokeAt = "", time.Time{}
			changed = true
		}
		if lease.State == leaseActive && !lease.ExpiresAt.After(now) {
			if err := c.issuer.Revoke(ctx, lease.BackendLeaseID); err != nil {
				return ErrUnavailable
			}
			lease.State, lease.Revision = leaseExpired, lease.Revision+1
			changed = true
		}
	}
	if changed {
		return c.persist()
	}
	return nil
}

func (c *Controller) consumeReplay(jti string, now time.Time) bool {
	retained := c.ledger.Replays[:0]
	for _, replay := range c.ledger.Replays {
		if replay.ExpiresAt.After(now) {
			retained = append(retained, replay)
			if replay.JTI == jti {
				c.ledger.Replays = retained
				return false
			}
		}
	}
	c.ledger.Replays = append(retained, ReplayRecord{JTI: jti, ExpiresAt: now.Add(time.Minute)})
	return len(c.ledger.Replays) <= maxLedgerItems
}

func (c *Controller) findLease(id string) (int, *LeaseRecord) {
	for index := range c.ledger.Leases {
		if c.ledger.Leases[index].LeaseID == id {
			copy := c.ledger.Leases[index]
			return index, &copy
		}
	}
	return -1, nil
}

func (c *Controller) persist() error {
	previous := c.ledger.Revision
	c.ledger.Revision++
	if err := saveLedger(c.ledgerPath, c.ledger); err != nil {
		c.ledger.Revision = previous
		return err
	}
	return nil
}

func (c *Controller) newLeaseID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(c.random, value); err != nil {
		return "", err
	}
	defer clear(value)
	return "lease2_" + hex.EncodeToString(value), nil
}

func issueSpec(policy Policy, leaseID string, ttl time.Duration) credentialbackend.IssueSpec {
	return credentialbackend.IssueSpec{SubjectID: policy.Principal.Name, SubjectDigest: policy.Principal.Digest(), PolicyID: policy.ID,
		Purpose:      string(policy.Purpose),
		PolicyDigest: policy.Digest(), BindingDigest: backendBindingDigest(policy), BackendID: policy.BackendID,
		BackendPolicy: policy.BackendPolicy, LeaseID: leaseID, TTL: ttl}
}

func backendBindingDigest(policy Policy) string {
	document := []byte(policy.Principal.Digest() + "\x00" + policy.Digest() + "\x00" + policy.BackendID + "\x00" + policy.BackendPolicy)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/workload-credential/backend-binding/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateIssued(issued credentialbackend.IssuedCredential, now time.Time, maxTTL time.Duration) error {
	if len(issued.Credential) < 1 || len(issued.Credential) > 1<<20 || len(issued.BackendLeaseID) < 8 || len(issued.BackendLeaseID) > 256 ||
		!issued.ExpiresAt.After(now) || issued.ExpiresAt.After(now.Add(maxTTL+time.Second)) {
		return ErrUnavailable
	}
	return nil
}

func ledgerLeaseFromIssued(policy Policy, leaseID string, issued credentialbackend.IssuedCredential, now time.Time, revision int64) LeaseRecord {
	digest := sha256.Sum256(issued.Credential)
	return LeaseRecord{LeaseID: leaseID, Principal: policy.Principal, PrincipalDigest: policy.Principal.Digest(), Purpose: policy.Purpose,
		PolicyID: policy.ID, PolicyDigest: policy.Digest(), BackendID: policy.BackendID, BackendPolicy: policy.BackendPolicy,
		BindingDigest: backendBindingDigest(policy), BackendLeaseID: issued.BackendLeaseID, CredentialDigest: "sha256:" + hex.EncodeToString(digest[:]),
		IssuedAt: now, ExpiresAt: issued.ExpiresAt.UTC(), Revision: revision, Renewable: policy.Renewable, State: leaseActive}
}

func leaseMatchesPolicy(lease LeaseRecord, policy Policy) bool {
	return lease.PrincipalDigest == policy.Principal.Digest() && lease.Purpose == policy.Purpose && lease.PolicyID == policy.ID &&
		lease.PolicyDigest == policy.Digest() && lease.BackendID == policy.BackendID && lease.BackendPolicy == policy.BackendPolicy &&
		lease.BindingDigest == backendBindingDigest(policy) && lease.Renewable == policy.Renewable
}

func okResponse(request Request, lease LeaseRecord, credential []byte) Response {
	return Response{Protocol: ProtocolID, Type: ResponseType, Status: StatusOK, RequestDigest: request.RequestDigest,
		PrincipalDigest: request.Principal.Digest(), PolicyDigest: request.PolicyDigest, LeaseID: lease.LeaseID, Revision: lease.Revision,
		IssuedAt: lease.IssuedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Renewable: lease.Renewable, Credential: append([]byte(nil), credential...)}
}

func errorResponse(request Request, status string) Response {
	return Response{Protocol: ProtocolID, Type: ResponseType, Status: status, RequestDigest: request.RequestDigest,
		PrincipalDigest: request.Principal.Digest(), PolicyDigest: request.PolicyDigest}
}

func statusError(status string) error {
	switch status {
	case StatusDenied:
		return ErrDenied
	case StatusExpired:
		return ErrExpired
	case StatusRevoked:
		return ErrRevoked
	default:
		return ErrUnavailable
	}
}

func normalizeIssuerError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}

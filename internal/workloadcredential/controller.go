package workloadcredential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	LedgerSchema   = "sandbox-runtime.workload-credential-ledger.v1"
	maxPolicies    = 64
	maxIdentities  = 64
	maxLedgerItems = 4096
)

type Policy struct {
	ID            string
	AgentID       string
	Role          secretref.Role
	Purpose       secretref.Purpose
	BindingDigest string
	BackendID     string
	MaxTTL        time.Duration
	Renewable     bool
	Migration     bool
}

type IssuedCredential struct {
	Credential     []byte
	BackendLeaseID string
	ExpiresAt      time.Time
}

func (c *IssuedCredential) Destroy() {
	if c != nil {
		clear(c.Credential)
	}
}

type IssueSpec struct {
	AgentID       string
	Role          secretref.Role
	Purpose       secretref.Purpose
	PolicyID      string
	BindingDigest string
	BackendID     string
	LeaseID       string
	TTL           time.Duration
}

type Issuer interface {
	Issue(context.Context, IssueSpec) (IssuedCredential, error)
	Verify(context.Context, IssuedCredential) error
	Revoke(context.Context, string) error
}

type ControllerConfig struct {
	LedgerPath string
	Identities map[string]ed25519.PublicKey
	Policies   []Policy
	Issuer     Issuer
	Overlap    time.Duration
	Now        func() time.Time
	Random     io.Reader
}

type Controller struct {
	mu         sync.Mutex
	ledgerPath string
	identities map[string]ed25519.PublicKey
	policies   map[string]Policy
	issuer     Issuer
	overlap    time.Duration
	now        func() time.Time
	random     io.Reader
	ledger     Ledger
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Issuer == nil || config.Now == nil || config.Now().IsZero() || config.Random == nil ||
		config.Overlap < time.Second || config.Overlap > 30*time.Second || len(config.Identities) < 1 || len(config.Identities) > maxIdentities ||
		len(config.Policies) < 1 || len(config.Policies) > maxPolicies {
		return nil, ErrUnavailable
	}
	controller := &Controller{
		ledgerPath: config.LedgerPath, identities: make(map[string]ed25519.PublicKey, len(config.Identities)),
		policies: make(map[string]Policy, len(config.Policies)), issuer: config.Issuer, overlap: config.Overlap,
		now: config.Now, random: config.Random,
	}
	for agentID, publicKey := range config.Identities {
		if !identifierPattern.MatchString(agentID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrUnavailable
		}
		controller.identities[agentID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	for _, policy := range config.Policies {
		if !validPolicy(policy) {
			return nil, ErrUnavailable
		}
		if _, ok := controller.identities[policy.AgentID]; !ok {
			return nil, ErrUnavailable
		}
		if _, duplicate := controller.policies[policy.ID]; duplicate {
			return nil, ErrUnavailable
		}
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

func (c *Controller) Handle(ctx context.Context, request Request) (Response, error) {
	if c == nil || ctx == nil {
		return Response{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	publicKey, known := c.identities[request.AgentID]
	if !known || request.Validate(now, publicKey) != nil {
		return deniedResponse(request), ErrDenied
	}
	policy, ok := c.policies[request.PolicyID]
	if !ok || !requestMatchesPolicy(request, policy) || c.replayAccepted(request.JTI, now) == false {
		return deniedResponse(request), ErrDenied
	}
	// Persist replay consumption before contacting the backend. A crash may
	// consume one JTI but can never replay a credential mutation.
	if err := c.persist(); err != nil {
		return unavailableResponse(request), ErrUnavailable
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
		return deniedResponse(request), ErrDenied
	}
}

func (c *Controller) issue(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	for _, lease := range c.ledger.Leases {
		if lease.AgentID == request.AgentID && lease.PolicyID == policy.ID && lease.State == leaseActive && lease.ExpiresAt.After(now) {
			return deniedResponse(request), ErrDenied
		}
	}
	leaseID, err := c.newLeaseID()
	if err != nil {
		return unavailableResponse(request), ErrUnavailable
	}
	ttl := min(time.Duration(request.RequestedTTL)*time.Second, policy.MaxTTL)
	issued, err := c.issuer.Issue(ctx, issueSpec(policy, leaseID, ttl))
	if err != nil || validateIssued(issued, now, ttl) != nil || c.issuer.Verify(ctx, issued) != nil {
		issued.Destroy()
		if issued.BackendLeaseID != "" {
			_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		}
		return unavailableResponse(request), ErrUnavailable
	}
	defer issued.Destroy()
	lease := ledgerLeaseFromIssued(policy, leaseID, issued, now, 1)
	c.ledger.Leases = append(c.ledger.Leases, lease)
	if err := c.persist(); err != nil {
		_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		return unavailableResponse(request), ErrUnavailable
	}
	return okResponse(request, lease, issued.Credential), nil
}

func (c *Controller) renew(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	index, lease := c.findLease(request.LeaseID)
	if lease == nil || !policy.Renewable || policy.Migration || lease.State != leaseActive || lease.Revision != request.Revision || !lease.ExpiresAt.After(now) || !leaseMatchesPolicy(*lease, policy) {
		return deniedResponse(request), ErrDenied
	}
	ttl := min(time.Duration(request.RequestedTTL)*time.Second, policy.MaxTTL)
	issued, err := c.issuer.Issue(ctx, issueSpec(policy, lease.LeaseID, ttl))
	if err != nil || validateIssued(issued, now, ttl) != nil || c.issuer.Verify(ctx, issued) != nil {
		issued.Destroy()
		if issued.BackendLeaseID != "" {
			_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		}
		return unavailableResponse(request), ErrUnavailable
	}
	defer issued.Destroy()
	replacement := ledgerLeaseFromIssued(policy, lease.LeaseID, issued, now, lease.Revision+1)
	replacement.PreviousBackendLeaseID = lease.BackendLeaseID
	replacement.PreviousRevokeAt = now.Add(c.overlap)
	c.ledger.Leases[index] = replacement
	if err := c.persist(); err != nil {
		_ = c.issuer.Revoke(context.WithoutCancel(ctx), issued.BackendLeaseID)
		return unavailableResponse(request), ErrUnavailable
	}
	return okResponse(request, replacement, issued.Credential), nil
}

func (c *Controller) revoke(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	index, lease := c.findLease(request.LeaseID)
	if lease == nil || lease.Revision != request.Revision || !leaseMatchesPolicy(*lease, policy) || lease.State != leaseActive {
		return deniedResponse(request), ErrDenied
	}
	if err := c.issuer.Revoke(ctx, lease.BackendLeaseID); err != nil {
		return unavailableResponse(request), ErrUnavailable
	}
	if lease.PreviousBackendLeaseID != "" {
		if err := c.issuer.Revoke(ctx, lease.PreviousBackendLeaseID); err != nil {
			return unavailableResponse(request), ErrUnavailable
		}
	}
	lease.State, lease.Revision, lease.RevokedAt = leaseRevoked, lease.Revision+1, now
	lease.PreviousBackendLeaseID, lease.PreviousRevokeAt = "", time.Time{}
	c.ledger.Leases[index] = *lease
	if err := c.persist(); err != nil {
		return unavailableResponse(request), ErrUnavailable
	}
	return okResponse(request, *lease, nil), nil
}

func (c *Controller) status(request Request, policy Policy, now time.Time) (Response, error) {
	_, lease := c.findLease(request.LeaseID)
	if lease == nil || lease.Revision != request.Revision || !leaseMatchesPolicy(*lease, policy) {
		return deniedResponse(request), ErrDenied
	}
	if lease.State == leaseRevoked {
		return revokedResponse(request), ErrRevoked
	}
	if !lease.ExpiresAt.After(now) {
		return expiredResponse(request), ErrExpired
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

func (c *Controller) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for index := range c.ledger.Leases {
		lease := &c.ledger.Leases[index]
		policy := c.policies[lease.PolicyID]
		if lease.State != leaseActive || !policy.Migration {
			continue
		}
		if err := c.issuer.Revoke(ctx, lease.BackendLeaseID); err != nil {
			return ErrUnavailable
		}
		lease.State, lease.Revision, lease.RevokedAt = leaseRevoked, lease.Revision+1, c.now().UTC()
	}
	return c.persist()
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

func (c *Controller) replayAccepted(jti string, now time.Time) bool {
	retained := c.ledger.Replays[:0]
	for _, replay := range c.ledger.Replays {
		if replay.ExpiresAt.After(now) {
			retained = append(retained, replay)
		}
		if replay.JTI == jti && replay.ExpiresAt.After(now) {
			c.ledger.Replays = retained
			return false
		}
	}
	c.ledger.Replays = append(retained, ReplayRecord{JTI: jti, ExpiresAt: now.Add(time.Minute)})
	return len(c.ledger.Replays) <= maxLedgerItems
}

func (c *Controller) persist() error {
	c.ledger.Revision++
	return saveLedger(c.ledgerPath, c.ledger)
}

func (c *Controller) newLeaseID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(c.random, value); err != nil {
		return "", err
	}
	defer clear(value)
	return "lease_" + hex.EncodeToString(value), nil
}

func validPolicy(policy Policy) bool {
	return identifierPattern.MatchString(policy.ID) && identifierPattern.MatchString(policy.AgentID) && validRole(policy.Role) &&
		validPurpose(policy.Purpose) && validDigest(policy.BindingDigest) && identifierPattern.MatchString(policy.BackendID) &&
		policy.MaxTTL >= 5*time.Second && policy.MaxTTL <= 15*time.Minute && (!policy.Migration || !policy.Renewable)
}

func requestMatchesPolicy(request Request, policy Policy) bool {
	return request.AgentID == policy.AgentID && request.Role == policy.Role && request.Purpose == policy.Purpose &&
		request.PolicyID == policy.ID && request.BindingDigest == policy.BindingDigest && request.BackendID == policy.BackendID
}

func leaseMatchesPolicy(lease LeaseRecord, policy Policy) bool {
	return lease.AgentID == policy.AgentID && lease.Role == policy.Role && lease.Purpose == policy.Purpose && lease.PolicyID == policy.ID &&
		lease.BindingDigest == policy.BindingDigest && lease.BackendID == policy.BackendID && lease.Renewable == policy.Renewable && lease.Migration == policy.Migration
}

func issueSpec(policy Policy, leaseID string, ttl time.Duration) IssueSpec {
	return IssueSpec{AgentID: policy.AgentID, Role: policy.Role, Purpose: policy.Purpose, PolicyID: policy.ID, BindingDigest: policy.BindingDigest, BackendID: policy.BackendID, LeaseID: leaseID, TTL: ttl}
}

func validateIssued(issued IssuedCredential, now time.Time, maxTTL time.Duration) error {
	if len(issued.Credential) < 1 || len(issued.Credential) > secretref.MaxSecretBytes || !backendLeasePattern.MatchString(issued.BackendLeaseID) ||
		!issued.ExpiresAt.After(now) || issued.ExpiresAt.After(now.Add(maxTTL+time.Second)) {
		return ErrUnavailable
	}
	return nil
}

func ledgerLeaseFromIssued(policy Policy, leaseID string, issued IssuedCredential, now time.Time, revision int64) LeaseRecord {
	digest := sha256.Sum256(issued.Credential)
	return LeaseRecord{
		LeaseID: leaseID, AgentID: policy.AgentID, Role: policy.Role, Purpose: policy.Purpose, PolicyID: policy.ID,
		BindingDigest: policy.BindingDigest, BackendID: policy.BackendID, BackendLeaseID: issued.BackendLeaseID,
		CredentialDigest: "sha256:" + hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: issued.ExpiresAt.UTC(),
		Revision: revision, Renewable: policy.Renewable, Migration: policy.Migration, State: leaseActive,
	}
}

func okResponse(request Request, lease LeaseRecord, credential []byte) Response {
	return Response{Protocol: ProtocolID, Type: ResponseType, Status: StatusOK, RequestDigest: request.RequestDigest, AgentID: request.AgentID,
		LeaseID: lease.LeaseID, Revision: lease.Revision, IssuedAt: lease.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339Nano), Renewable: lease.Renewable, Credential: append([]byte(nil), credential...)}
}

func deniedResponse(request Request) Response      { return errorResponse(request, StatusDenied) }
func unavailableResponse(request Request) Response { return errorResponse(request, StatusUnavailable) }
func expiredResponse(request Request) Response     { return errorResponse(request, StatusExpired) }
func revokedResponse(request Request) Response     { return errorResponse(request, StatusRevoked) }

func errorResponse(request Request, status string) Response {
	return Response{Protocol: ProtocolID, Type: ResponseType, Status: status, RequestDigest: request.RequestDigest, AgentID: request.AgentID}
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

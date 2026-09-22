package workloadpki

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

const (
	LedgerSchema          = "sandbox-runtime.workload-certificate-ledger.v1"
	certificateActive     = "active"
	certificateRevoked    = "revoked"
	certificateExpired    = "expired"
	maxControllerPolicies = 128
	maxLedgerRecords      = 8192
	maxActiveCertificates = 2
)

type CertificateAuthority interface {
	Issue(context.Context, Policy, []byte, time.Duration) (IssuedCertificate, error)
	Revocations(context.Context) (RevocationSnapshot, error)
	Revoke(context.Context, string) error
}

type ControllerConfig struct {
	LedgerPath       string
	Policies         []Policy
	Authority        CertificateAuthority
	ControllerKeyID  string
	ControllerKey    ed25519.PrivateKey
	Now              func() time.Time
	MaximumActive    int
	MaximumLedgerAge time.Duration
}

type Controller struct {
	mu               sync.Mutex
	ledgerPath       string
	policies         map[string]Policy
	authority        CertificateAuthority
	controllerKeyID  string
	controllerKey    ed25519.PrivateKey
	now              func() time.Time
	maximumActive    int
	maximumLedgerAge time.Duration
	ledger           Ledger
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Authority == nil || !namePattern.MatchString(config.ControllerKeyID) || len(config.ControllerKey) != ed25519.PrivateKeySize ||
		config.Now == nil || config.Now().IsZero() || len(config.Policies) < 1 || len(config.Policies) > maxControllerPolicies ||
		config.MaximumActive < 1 || config.MaximumActive > maxActiveCertificates || config.MaximumLedgerAge < time.Hour || config.MaximumLedgerAge > 7*24*time.Hour {
		return nil, ErrUnavailable
	}
	controller := &Controller{ledgerPath: config.LedgerPath, policies: make(map[string]Policy, len(config.Policies)), authority: config.Authority,
		controllerKeyID: config.ControllerKeyID, controllerKey: append(ed25519.PrivateKey(nil), config.ControllerKey...), now: config.Now,
		maximumActive: config.MaximumActive, maximumLedgerAge: config.MaximumLedgerAge}
	for _, policy := range config.Policies {
		if policy.Validate() != nil {
			controller.Close()
			return nil, ErrUnavailable
		}
		if _, duplicate := controller.policies[policy.ID]; duplicate {
			controller.Close()
			return nil, ErrUnavailable
		}
		policy.PublicKey = append(ed25519.PublicKey(nil), policy.PublicKey...)
		policy.DNSNames = append([]string(nil), policy.DNSNames...)
		policy.Usages = append([]string(nil), policy.Usages...)
		controller.policies[policy.ID] = policy
	}
	ledger, err := loadLedger(config.LedgerPath)
	if err != nil {
		controller.Close()
		return nil, err
	}
	controller.ledger = ledger
	if controller.ledger.Schema == "" {
		controller.ledger = Ledger{Schema: LedgerSchema, Revision: 1}
		if err := saveLedger(controller.ledgerPath, controller.ledger); err != nil {
			controller.Close()
			return nil, err
		}
	}
	if controller.validateLedger() != nil {
		controller.Close()
		return nil, ErrUnavailable
	}
	return controller, nil
}

func (c *Controller) Close() {
	if c == nil {
		return
	}
	clear(c.controllerKey)
	c.controllerKey = nil
	for id, policy := range c.policies {
		clear(policy.PublicKey)
		delete(c.policies, id)
	}
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
	policy, known := c.policies[request.PolicyID]
	if !known || policy.ExpectedUID != peerUID || policy.ExpectedGID != peerGID || request.Validate(policy, now) != nil {
		return c.errorResponse(request, StatusDenied, ErrDenied)
	}
	if !c.consumeReplay(request.Nonce, request.Deadline, now) {
		return c.errorResponse(request, StatusDenied, ErrDenied)
	}
	// Persist replay consumption before any PKI operation. A crash may consume
	// one nonce but can never replay an issuance or revocation mutation.
	if err := c.persist(); err != nil {
		return c.errorResponse(request, StatusUnavailable, ErrUnavailable)
	}
	deadline, _ := parseTime(request.Deadline)
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	switch request.Type {
	case IssueType:
		return c.issue(operationContext, request, policy, now)
	case RevocationsType:
		return c.revocations(operationContext, request)
	case RevokeType:
		return c.revoke(operationContext, request, policy, now)
	default:
		return c.errorResponse(request, StatusDenied, ErrDenied)
	}
}

func (c *Controller) issue(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	active := 0
	for index := range c.ledger.Certificates {
		record := &c.ledger.Certificates[index]
		if record.PolicyID == policy.ID && record.State == certificateActive {
			if !record.NotAfter.After(now) {
				record.State = certificateExpired
				continue
			}
			active++
		}
	}
	if active >= c.maximumActive {
		return c.errorResponse(request, StatusDenied, ErrDenied)
	}
	issued, err := c.authority.Issue(ctx, policy, request.CSRPEM, time.Duration(request.RequestedTTLSeconds)*time.Second)
	if err != nil || validateAuthorityIssue(issued, now, time.Duration(request.RequestedTTLSeconds)*time.Second) != nil {
		issued.Destroy()
		return c.errorResponse(request, StatusUnavailable, normalizeAuthorityError(err))
	}
	defer issued.Destroy()
	record := CertificateRecord{Serial: issued.Serial, AgentID: policy.Requester.Name, RequesterDigest: policy.Requester.Digest(), PolicyID: policy.ID,
		Principal: policy.Subject.Name, SubjectDigest: policy.Subject.Digest(),
		IssuerRevision: issued.IssuerRevision, CertificateDigest: certificateDigest(issued.CertificatePEM), NotBefore: issued.NotBefore,
		NotAfter: issued.NotAfter, IssuedAt: now, State: certificateActive}
	for _, existing := range c.ledger.Certificates {
		if existing.Serial == record.Serial {
			_ = c.authority.Revoke(context.WithoutCancel(ctx), issued.Serial)
			return c.errorResponse(request, StatusUnavailable, ErrUnavailable)
		}
	}
	c.ledger.Certificates = append(c.ledger.Certificates, record)
	if err := c.persist(); err != nil {
		_ = c.authority.Revoke(context.WithoutCancel(ctx), issued.Serial)
		return c.errorResponse(request, StatusUnavailable, ErrUnavailable)
	}
	return c.successResponse(request, Response{Type: CertificateType, Status: StatusOK, IssuerRevision: issued.IssuerRevision,
		CertificatePEM: append([]byte(nil), issued.CertificatePEM...), IssuingCAPEM: append([]byte(nil), issued.IssuingCAPEM...),
		CAChainPEM: append([]byte(nil), issued.CAChainPEM...), Serial: issued.Serial, NotBefore: issued.NotBefore.Format(time.RFC3339Nano),
		NotAfter: issued.NotAfter.Format(time.RFC3339Nano)})
}

func (c *Controller) revocations(ctx context.Context, request Request) (Response, error) {
	snapshot, err := c.authority.Revocations(ctx)
	if err != nil || len(snapshot.DER) < 1 || snapshot.ThisUpdate.IsZero() || snapshot.NextUpdate.IsZero() || !snapshot.NextUpdate.After(snapshot.ThisUpdate) {
		snapshot.Destroy()
		return c.errorResponse(request, StatusUnavailable, normalizeAuthorityError(err))
	}
	defer snapshot.Destroy()
	return c.successResponse(request, Response{Type: RevocationSnapshotType, Status: StatusOK, IssuerRevision: snapshot.IssuerRevision,
		CRLDER: append([]byte(nil), snapshot.DER...), CRLThisUpdate: snapshot.ThisUpdate.Format(time.RFC3339Nano), CRLNextUpdate: snapshot.NextUpdate.Format(time.RFC3339Nano)})
}

func (c *Controller) revoke(ctx context.Context, request Request, policy Policy, now time.Time) (Response, error) {
	index := -1
	for candidate := range c.ledger.Certificates {
		record := c.ledger.Certificates[candidate]
		if record.Serial == request.Serial && record.AgentID == policy.Requester.Name && record.RequesterDigest == policy.Requester.Digest() &&
			record.PolicyID == policy.ID && record.Principal == policy.Subject.Name && record.SubjectDigest == policy.Subject.Digest() && record.State == certificateActive {
			index = candidate
			break
		}
	}
	if index < 0 {
		return c.errorResponse(request, StatusDenied, ErrDenied)
	}
	if err := c.authority.Revoke(ctx, request.Serial); err != nil {
		return c.errorResponse(request, StatusUnavailable, normalizeAuthorityError(err))
	}
	c.ledger.Certificates[index].State = certificateRevoked
	c.ledger.Certificates[index].RevokedAt = now
	if err := c.persist(); err != nil {
		return c.errorResponse(request, StatusUnavailable, ErrUnavailable)
	}
	return c.successResponse(request, Response{Type: RevokedType, Status: StatusOK,
		IssuerRevision: c.ledger.Certificates[index].IssuerRevision, Serial: request.Serial, Revoked: true})
}

func (c *Controller) Reap() error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	changed := false
	for index := range c.ledger.Certificates {
		record := &c.ledger.Certificates[index]
		if record.State == certificateActive && !record.NotAfter.After(now) {
			record.State = certificateExpired
			changed = true
		}
	}
	keptReplays := c.ledger.Replays[:0]
	for _, replay := range c.ledger.Replays {
		if replay.ExpiresAt.Add(c.maximumLedgerAge).After(now) {
			keptReplays = append(keptReplays, replay)
		} else {
			changed = true
		}
	}
	c.ledger.Replays = keptReplays
	if changed {
		return c.persist()
	}
	return nil
}

func (c *Controller) consumeReplay(nonce, deadlineValue string, now time.Time) bool {
	deadline, err := parseTime(deadlineValue)
	if err != nil {
		return false
	}
	for _, replay := range c.ledger.Replays {
		if replay.Nonce == nonce {
			return false
		}
	}
	if len(c.ledger.Replays) >= maxLedgerRecords {
		return false
	}
	c.ledger.Replays = append(c.ledger.Replays, ReplayRecord{Nonce: nonce, ExpiresAt: deadline, AcceptedAt: now})
	return true
}

func (c *Controller) successResponse(request Request, response Response) (Response, error) {
	sealed, err := NewResponse(request, response, c.controllerKeyID, c.controllerKey)
	if err != nil {
		return Response{}, ErrUnavailable
	}
	return sealed, nil
}

func (c *Controller) errorResponse(request Request, status string, result error) (Response, error) {
	sealed, err := NewResponse(request, Response{Type: ErrorType, Status: status}, c.controllerKeyID, c.controllerKey)
	if err != nil {
		return Response{}, result
	}
	return sealed, result
}

func validateAuthorityIssue(issued IssuedCertificate, now time.Time, ttl time.Duration) error {
	if !revisionPattern.MatchString(issued.IssuerRevision) || !serialPattern.MatchString(issued.Serial) || len(issued.CertificatePEM) < 1 ||
		len(issued.CertificatePEM) > maxPEMBytes || len(issued.IssuingCAPEM) < 1 || len(issued.IssuingCAPEM) > maxPEMBytes ||
		len(issued.CAChainPEM) < 1 || len(issued.CAChainPEM) > maxPEMBytes || issued.NotBefore.After(now) || !issued.NotAfter.After(now) ||
		issued.NotAfter.Sub(issued.NotBefore) <= 0 || issued.NotAfter.Sub(issued.NotBefore) > ttl+2*time.Minute {
		return ErrUnavailable
	}
	return nil
}

func normalizeAuthorityError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}

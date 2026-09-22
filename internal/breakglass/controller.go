// Package breakglass implements a separate, operator-owned emergency-access
// authority. Capabilities are unusable offline: every use must be atomically
// consumed against this controller's persistent single-use ledger.
package breakglass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	ProtocolID       = "sandbox-runtime.break-glass.v1"
	LedgerSchema     = "sandbox-runtime.break-glass-ledger.v1"
	AuditSchema      = "sandbox-runtime.break-glass-audit.v1"
	CapabilitySchema = "sandbox-runtime.break-glass-capability.v1"

	ActorRequester = "requester"
	ActorApprover  = "approver"
	ActorOperator  = "operator"
	ActorTarget    = "target-agent"

	CommandIssue  = "issue"
	CommandRevoke = "revoke"

	StatePending  = "pending"
	StateIssued   = "issued"
	StateConsumed = "consumed"
	StateRevoked  = "revoked"
	StateExpired  = "expired"

	maxRecords = 4096
)

var (
	ErrDenied      = errors.New("break-glass request denied")
	ErrUnavailable = errors.New("break-glass controller unavailable")
	ErrExpired     = errors.New("break-glass capability expired")
	ErrRevoked     = errors.New("break-glass capability revoked")
	ErrConsumed    = errors.New("break-glass capability already consumed")

	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	requestPattern    = regexp.MustCompile(`^bgreq_[0-9a-f]{32}$`)
	capabilityPattern = regexp.MustCompile(`^bgcap_[0-9a-f]{32}$`)
	tenantPattern     = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	operationPattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

type Actor struct {
	ID        string
	Kind      string
	PublicKey ed25519.PublicKey
}

type AccessRequest struct {
	Protocol            string            `json:"protocol"`
	RequestID           string            `json:"request_id"`
	RequesterID         string            `json:"requester_id"`
	TargetAgentID       string            `json:"target_agent_id"`
	Role                secretref.Role    `json:"role"`
	Purpose             secretref.Purpose `json:"purpose"`
	BindingDigest       string            `json:"binding_digest"`
	TenantID            string            `json:"tenant_id"`
	Operation           string            `json:"operation"`
	ReasonDigest        string            `json:"reason_digest"`
	TicketDigest        string            `json:"ticket_digest"`
	RequestedTTLSeconds int64             `json:"requested_ttl_seconds"`
	Deadline            string            `json:"deadline"`
	JTI                 string            `json:"jti"`
	RequestDigest       string            `json:"request_digest"`
	Signature           string            `json:"signature"`
}

type Approval struct {
	Protocol      string `json:"protocol"`
	RequestID     string `json:"request_id"`
	RequestDigest string `json:"request_digest"`
	Revision      int64  `json:"revision"`
	ApproverID    string `json:"approver_id"`
	Deadline      string `json:"deadline"`
	JTI           string `json:"jti"`
	Digest        string `json:"digest"`
	Signature     string `json:"signature"`
}

type Command struct {
	Protocol  string `json:"protocol"`
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Revision  int64  `json:"revision"`
	ActorID   string `json:"actor_id"`
	Deadline  string `json:"deadline"`
	JTI       string `json:"jti"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type Capability struct {
	Schema        string            `json:"schema"`
	CapabilityID  string            `json:"capability_id"`
	RequestID     string            `json:"request_id"`
	RequestDigest string            `json:"request_digest"`
	TargetAgentID string            `json:"target_agent_id"`
	Role          secretref.Role    `json:"role"`
	Purpose       secretref.Purpose `json:"purpose"`
	BindingDigest string            `json:"binding_digest"`
	TenantID      string            `json:"tenant_id"`
	Operation     string            `json:"operation"`
	IssuedAt      string            `json:"issued_at"`
	ExpiresAt     string            `json:"expires_at"`
	MaxUses       int               `json:"max_uses"`
	Revision      int64             `json:"revision"`
	Digest        string            `json:"digest"`
	Signature     string            `json:"signature"`
}

type Consume struct {
	Protocol      string     `json:"protocol"`
	Capability    Capability `json:"capability"`
	TargetAgentID string     `json:"target_agent_id"`
	Deadline      string     `json:"deadline"`
	JTI           string     `json:"jti"`
	Digest        string     `json:"digest"`
	Signature     string     `json:"signature"`
}

type Config struct {
	LedgerPath           string
	AuditPath            string
	Actors               []Actor
	ControllerPrivateKey ed25519.PrivateKey
	MaxTTL               time.Duration
	Now                  func() time.Time
	Random               io.Reader
}

type Controller struct {
	mu         sync.Mutex
	ledgerPath string
	auditPath  string
	actors     map[string]Actor
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	maxTTL     time.Duration
	now        func() time.Time
	random     io.Reader
	ledger     Ledger
}

type Ledger struct {
	Schema     string          `json:"schema"`
	Revision   int64           `json:"revision"`
	AuditHead  string          `json:"audit_head"`
	AuditCount int64           `json:"audit_count"`
	Requests   []RequestRecord `json:"requests"`
	Replays    []ReplayRecord  `json:"replays"`
}

type RequestRecord struct {
	Request      AccessRequest `json:"request"`
	Revision     int64         `json:"revision"`
	State        string        `json:"state"`
	ApproverIDs  []string      `json:"approver_ids"`
	CapabilityID string        `json:"capability_id"`
	IssuedAt     string        `json:"issued_at"`
	ExpiresAt    string        `json:"expires_at"`
	Uses         int           `json:"uses"`
	RevokedAt    string        `json:"revoked_at"`
}

type ReplayRecord struct {
	JTI       string `json:"jti"`
	ExpiresAt string `json:"expires_at"`
}

type AuditEntry struct {
	Schema        string            `json:"schema"`
	Sequence      int64             `json:"sequence"`
	ObservedAt    string            `json:"observed_at"`
	Event         string            `json:"event"`
	ActorID       string            `json:"actor_id"`
	RequestID     string            `json:"request_id"`
	CapabilityID  string            `json:"capability_id"`
	Role          secretref.Role    `json:"role"`
	Purpose       secretref.Purpose `json:"purpose"`
	BindingDigest string            `json:"binding_digest"`
	TenantID      string            `json:"tenant_id"`
	Operation     string            `json:"operation"`
	ReasonDigest  string            `json:"reason_digest"`
	TicketDigest  string            `json:"ticket_digest"`
	Revision      int64             `json:"revision"`
	PreviousHash  string            `json:"previous_hash"`
	EntryHash     string            `json:"entry_hash"`
}

func New(config Config) (*Controller, error) {
	if !validPrivatePath(config.LedgerPath) || !validPrivatePath(config.AuditPath) || config.LedgerPath == config.AuditPath ||
		len(config.Actors) < 5 || len(config.Actors) > 256 || len(config.ControllerPrivateKey) != ed25519.PrivateKeySize ||
		config.MaxTTL < time.Minute || config.MaxTTL > 15*time.Minute || config.Now == nil || config.Now().IsZero() || config.Random == nil {
		return nil, ErrUnavailable
	}
	controller := &Controller{ledgerPath: config.LedgerPath, auditPath: config.AuditPath, actors: make(map[string]Actor, len(config.Actors)),
		privateKey: append(ed25519.PrivateKey(nil), config.ControllerPrivateKey...), publicKey: append(ed25519.PublicKey(nil), config.ControllerPrivateKey.Public().(ed25519.PublicKey)...),
		maxTTL: config.MaxTTL, now: config.Now, random: config.Random}
	kinds := make(map[string]int)
	for _, actor := range config.Actors {
		if !identifierPattern.MatchString(actor.ID) || !validActorKind(actor.Kind) || len(actor.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrUnavailable
		}
		if _, duplicate := controller.actors[actor.ID]; duplicate {
			return nil, ErrUnavailable
		}
		actor.PublicKey = append(ed25519.PublicKey(nil), actor.PublicKey...)
		controller.actors[actor.ID] = actor
		kinds[actor.Kind]++
	}
	if kinds[ActorRequester] < 1 || kinds[ActorApprover] < 2 || kinds[ActorOperator] < 1 || kinds[ActorTarget] < 1 {
		return nil, ErrUnavailable
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
		if err := initializeAudit(config.AuditPath); err != nil {
			return nil, err
		}
	}
	if controller.validateLedger() != nil || verifyAudit(config.AuditPath, controller.ledger.AuditCount, controller.ledger.AuditHead) != nil {
		return nil, ErrUnavailable
	}
	return controller, nil
}

func NewProduction(config Config) (*Controller, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return New(config)
}

func (c *Controller) Close() {
	if c != nil {
		clear(c.privateKey)
	}
}

func (c *Controller) Submit(_ context.Context, request AccessRequest) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	actor, ok := c.actors[request.RequesterID]
	if !ok || actor.Kind != ActorRequester || validateAccessRequest(request, now, actor.PublicKey, c.maxTTL) != nil || request.RequesterID == request.TargetAgentID {
		return 0, ErrDenied
	}
	target, ok := c.actors[request.TargetAgentID]
	if !ok || target.Kind != ActorTarget || request.Purpose == secretref.PurposePostgresMigrationDSN || !c.acceptReplay(request.JTI, now) {
		return 0, ErrDenied
	}
	if _, record := c.findRequest(request.RequestID); record != nil {
		return 0, ErrDenied
	}
	record := RequestRecord{Request: request, Revision: 1, State: StatePending, ApproverIDs: []string{}}
	c.ledger.Requests = append(c.ledger.Requests, record)
	if err := c.commit("request.submitted", request.RequesterID, record); err != nil {
		return 0, err
	}
	return record.Revision, nil
}

func (c *Controller) Approve(_ context.Context, approval Approval) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	actor, ok := c.actors[approval.ApproverID]
	if !ok || actor.Kind != ActorApprover || validateApproval(approval, now, actor.PublicKey) != nil || !c.acceptReplay(approval.JTI, now) {
		return 0, ErrDenied
	}
	index, record := c.findRequest(approval.RequestID)
	if record == nil || record.State != StatePending || record.Revision != approval.Revision || record.Request.RequestDigest != approval.RequestDigest ||
		approval.ApproverID == record.Request.RequesterID || approval.ApproverID == record.Request.TargetAgentID || slicesContains(record.ApproverIDs, approval.ApproverID) || len(record.ApproverIDs) >= 2 {
		return 0, ErrDenied
	}
	record.ApproverIDs = append(record.ApproverIDs, approval.ApproverID)
	sort.Strings(record.ApproverIDs)
	record.Revision++
	c.ledger.Requests[index] = *record
	if err := c.commit("request.approved", approval.ApproverID, *record); err != nil {
		return 0, err
	}
	return record.Revision, nil
}

func (c *Controller) Issue(_ context.Context, command Command) (Capability, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	actor, ok := c.actors[command.ActorID]
	if !ok || actor.Kind != ActorOperator || validateCommand(command, CommandIssue, now, actor.PublicKey) != nil || !c.acceptReplay(command.JTI, now) {
		return Capability{}, ErrDenied
	}
	index, record := c.findRequest(command.RequestID)
	if record == nil || record.State != StatePending || record.Revision != command.Revision || len(record.ApproverIDs) != 2 {
		return Capability{}, ErrDenied
	}
	capabilityID, err := c.randomID("bgcap_")
	if err != nil {
		return Capability{}, ErrUnavailable
	}
	ttl := min(time.Duration(record.Request.RequestedTTLSeconds)*time.Second, c.maxTTL)
	capability := Capability{Schema: CapabilitySchema, CapabilityID: capabilityID, RequestID: record.Request.RequestID,
		RequestDigest: record.Request.RequestDigest, TargetAgentID: record.Request.TargetAgentID, Role: record.Request.Role,
		Purpose: record.Request.Purpose, BindingDigest: record.Request.BindingDigest, TenantID: record.Request.TenantID,
		Operation: record.Request.Operation, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(ttl).Format(time.RFC3339Nano), MaxUses: 1, Revision: 1}
	capability.Digest = capabilityDigest(capability)
	capability.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.privateKey, []byte(capability.Digest)))
	if validateCapability(capability, now, c.publicKey) != nil {
		return Capability{}, ErrUnavailable
	}
	record.State, record.CapabilityID, record.IssuedAt, record.ExpiresAt = StateIssued, capabilityID, capability.IssuedAt, capability.ExpiresAt
	record.Revision++
	c.ledger.Requests[index] = *record
	if err := c.commit("capability.issued", command.ActorID, *record); err != nil {
		return Capability{}, err
	}
	return capability, nil
}

func (c *Controller) Consume(_ context.Context, consume Consume) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	actor, ok := c.actors[consume.TargetAgentID]
	if !ok || actor.Kind != ActorTarget || validateConsume(consume, now, actor.PublicKey, c.publicKey) != nil || !c.acceptReplay(consume.JTI, now) {
		return ErrDenied
	}
	index, record := c.findRequest(consume.Capability.RequestID)
	if record == nil || record.CapabilityID != consume.Capability.CapabilityID || record.Request.RequestDigest != consume.Capability.RequestDigest || record.Request.TargetAgentID != consume.TargetAgentID {
		return ErrDenied
	}
	if record.State == StateRevoked {
		return ErrRevoked
	}
	if record.State == StateConsumed || record.Uses >= 1 {
		return ErrConsumed
	}
	expiresAt, _ := parseTime(record.ExpiresAt)
	if record.State != StateIssued || !expiresAt.After(now) {
		record.State, record.Revision = StateExpired, record.Revision+1
		c.ledger.Requests[index] = *record
		_ = c.commit("capability.expired", consume.TargetAgentID, *record)
		return ErrExpired
	}
	record.Uses, record.State, record.Revision = record.Uses+1, StateConsumed, record.Revision+1
	c.ledger.Requests[index] = *record
	return c.commit("capability.consumed", consume.TargetAgentID, *record)
}

func (c *Controller) Revoke(_ context.Context, command Command) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	actor, ok := c.actors[command.ActorID]
	if !ok || actor.Kind != ActorOperator || validateCommand(command, CommandRevoke, now, actor.PublicKey) != nil || !c.acceptReplay(command.JTI, now) {
		return ErrDenied
	}
	index, record := c.findRequest(command.RequestID)
	if record == nil || record.Revision != command.Revision || (record.State != StateIssued && record.State != StatePending) {
		return ErrDenied
	}
	record.State, record.Revision, record.RevokedAt = StateRevoked, record.Revision+1, now.Format(time.RFC3339Nano)
	c.ledger.Requests[index] = *record
	return c.commit("capability.revoked", command.ActorID, *record)
}

func (c *Controller) commit(event, actorID string, record RequestRecord) error {
	entry := AuditEntry{Schema: AuditSchema, Sequence: c.ledger.AuditCount + 1, ObservedAt: c.now().UTC().Format(time.RFC3339Nano),
		Event: event, ActorID: actorID, RequestID: record.Request.RequestID, CapabilityID: record.CapabilityID,
		Role: record.Request.Role, Purpose: record.Request.Purpose, BindingDigest: record.Request.BindingDigest, TenantID: record.Request.TenantID,
		Operation: record.Request.Operation, ReasonDigest: record.Request.ReasonDigest, TicketDigest: record.Request.TicketDigest,
		Revision: record.Revision, PreviousHash: c.ledger.AuditHead}
	entry.EntryHash = auditDigest(entry)
	if err := appendAudit(c.auditPath, entry); err != nil {
		return ErrUnavailable
	}
	c.ledger.AuditCount, c.ledger.AuditHead, c.ledger.Revision = entry.Sequence, entry.EntryHash, c.ledger.Revision+1
	if err := saveLedger(c.ledgerPath, c.ledger); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Controller) acceptReplay(jti string, now time.Time) bool {
	retained := c.ledger.Replays[:0]
	for _, replay := range c.ledger.Replays {
		expires, err := parseTime(replay.ExpiresAt)
		if err != nil {
			return false
		}
		if expires.After(now) {
			if replay.JTI == jti {
				return false
			}
			retained = append(retained, replay)
		}
	}
	c.ledger.Replays = append(retained, ReplayRecord{JTI: jti, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
	return len(c.ledger.Replays) <= maxRecords
}

func (c *Controller) findRequest(id string) (int, *RequestRecord) {
	for index := range c.ledger.Requests {
		if c.ledger.Requests[index].Request.RequestID == id {
			copy := c.ledger.Requests[index]
			return index, &copy
		}
	}
	return -1, nil
}

func (c *Controller) randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(c.random, value); err != nil {
		return "", err
	}
	defer clear(value)
	return prefix + hex.EncodeToString(value), nil
}

func (c *Controller) validateLedger() error {
	if c.ledger.Schema != LedgerSchema || c.ledger.Revision < 1 || len(c.ledger.Requests) > maxRecords || len(c.ledger.Replays) > maxRecords ||
		(c.ledger.AuditCount == 0) != (c.ledger.AuditHead == "") || (c.ledger.AuditHead != "" && !validDigest(c.ledger.AuditHead)) {
		return ErrUnavailable
	}
	seen := make(map[string]struct{}, len(c.ledger.Requests))
	for _, record := range c.ledger.Requests {
		requester := c.actors[record.Request.RequesterID]
		if validateAccessRequest(record.Request, time.Time{}, requester.PublicKey, c.maxTTL) != nil || record.Revision < 1 || !validState(record.State) || len(record.ApproverIDs) > 2 || record.Uses < 0 || record.Uses > 1 {
			return ErrUnavailable
		}
		if _, duplicate := seen[record.Request.RequestID]; duplicate {
			return ErrUnavailable
		}
		seen[record.Request.RequestID] = struct{}{}
	}
	return nil
}

func NewSignedAccessRequest(request AccessRequest, key ed25519.PrivateKey) (AccessRequest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return AccessRequest{}, ErrDenied
	}
	request.Protocol = ProtocolID
	request.RequestDigest = accessRequestDigest(request)
	request.Signature = signDigest(key, request.RequestDigest)
	return request, nil
}

func NewSignedApproval(approval Approval, key ed25519.PrivateKey) (Approval, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Approval{}, ErrDenied
	}
	approval.Protocol = ProtocolID
	approval.Digest = approvalDigest(approval)
	approval.Signature = signDigest(key, approval.Digest)
	return approval, nil
}

func NewSignedCommand(command Command, key ed25519.PrivateKey) (Command, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Command{}, ErrDenied
	}
	command.Protocol = ProtocolID
	command.Digest = commandDigest(command)
	command.Signature = signDigest(key, command.Digest)
	return command, nil
}

func NewSignedConsume(consume Consume, key ed25519.PrivateKey) (Consume, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Consume{}, ErrDenied
	}
	consume.Protocol = ProtocolID
	consume.Digest = consumeDigest(consume)
	consume.Signature = signDigest(key, consume.Digest)
	return consume, nil
}

func validateAccessRequest(request AccessRequest, now time.Time, publicKey ed25519.PublicKey, maxTTL time.Duration) error {
	deadline, deadlineErr := parseTime(request.Deadline)
	if request.Protocol != ProtocolID || !requestPattern.MatchString(request.RequestID) || !identifierPattern.MatchString(request.RequesterID) ||
		!identifierPattern.MatchString(request.TargetAgentID) || !validRole(request.Role) || !validPurpose(request.Purpose) || !validDigest(request.BindingDigest) ||
		!validTenant(request.TenantID) || !operationPattern.MatchString(request.Operation) || !validDigest(request.ReasonDigest) || !validDigest(request.TicketDigest) ||
		request.RequestedTTLSeconds < 1 || time.Duration(request.RequestedTTLSeconds)*time.Second > maxTTL || deadlineErr != nil || !validJTI(request.JTI) ||
		request.RequestDigest != accessRequestDigest(request) || !verifyDigest(publicKey, request.RequestDigest, request.Signature) {
		return ErrDenied
	}
	if !now.IsZero() && (!deadline.After(now) || deadline.After(now.Add(time.Minute))) {
		return ErrDenied
	}
	return nil
}

func validateApproval(approval Approval, now time.Time, publicKey ed25519.PublicKey) error {
	deadline, err := parseTime(approval.Deadline)
	if approval.Protocol != ProtocolID || !requestPattern.MatchString(approval.RequestID) || !validDigest(approval.RequestDigest) || approval.Revision < 1 ||
		!identifierPattern.MatchString(approval.ApproverID) || err != nil || !deadline.After(now) || deadline.After(now.Add(time.Minute)) || !validJTI(approval.JTI) ||
		approval.Digest != approvalDigest(approval) || !verifyDigest(publicKey, approval.Digest, approval.Signature) {
		return ErrDenied
	}
	return nil
}

func validateCommand(command Command, want string, now time.Time, publicKey ed25519.PublicKey) error {
	deadline, err := parseTime(command.Deadline)
	if command.Protocol != ProtocolID || command.Type != want || !requestPattern.MatchString(command.RequestID) || command.Revision < 1 ||
		!identifierPattern.MatchString(command.ActorID) || err != nil || !deadline.After(now) || deadline.After(now.Add(time.Minute)) || !validJTI(command.JTI) ||
		command.Digest != commandDigest(command) || !verifyDigest(publicKey, command.Digest, command.Signature) {
		return ErrDenied
	}
	return nil
}

func validateCapability(capability Capability, now time.Time, publicKey ed25519.PublicKey) error {
	issuedAt, issuedErr := parseTime(capability.IssuedAt)
	expiresAt, expiresErr := parseTime(capability.ExpiresAt)
	if capability.Schema != CapabilitySchema || !capabilityPattern.MatchString(capability.CapabilityID) || !requestPattern.MatchString(capability.RequestID) ||
		!validDigest(capability.RequestDigest) || !identifierPattern.MatchString(capability.TargetAgentID) || !validRole(capability.Role) || !validPurpose(capability.Purpose) ||
		!validDigest(capability.BindingDigest) || !validTenant(capability.TenantID) || !operationPattern.MatchString(capability.Operation) || issuedErr != nil || expiresErr != nil ||
		capability.MaxUses != 1 || capability.Revision != 1 || capability.Digest != capabilityDigest(capability) || !verifyDigest(publicKey, capability.Digest, capability.Signature) ||
		expiresAt.Before(issuedAt) || (!now.IsZero() && (!expiresAt.After(now) || issuedAt.After(now))) {
		return ErrDenied
	}
	return nil
}

func validateConsume(consume Consume, now time.Time, targetKey, controllerKey ed25519.PublicKey) error {
	deadline, err := parseTime(consume.Deadline)
	// Expiry is persistent controller state, not an offline capability-parser
	// decision. Verify the controller signature and closed capability shape here,
	// then let Consume atomically transition the matching issued record to
	// expired and append its audit entry below the controller lock.
	if consume.Protocol != ProtocolID || validateCapability(consume.Capability, time.Time{}, controllerKey) != nil || consume.TargetAgentID != consume.Capability.TargetAgentID ||
		err != nil || !deadline.After(now) || deadline.After(now.Add(time.Minute)) || !validJTI(consume.JTI) || consume.Digest != consumeDigest(consume) || !verifyDigest(targetKey, consume.Digest, consume.Signature) {
		return ErrDenied
	}
	return nil
}

func accessRequestDigest(value AccessRequest) string {
	return digest("sandbox-runtime/break-glass/request/v1", struct {
		Protocol            string            `json:"protocol"`
		RequestID           string            `json:"request_id"`
		RequesterID         string            `json:"requester_id"`
		TargetAgentID       string            `json:"target_agent_id"`
		Role                secretref.Role    `json:"role"`
		Purpose             secretref.Purpose `json:"purpose"`
		BindingDigest       string            `json:"binding_digest"`
		TenantID            string            `json:"tenant_id"`
		Operation           string            `json:"operation"`
		ReasonDigest        string            `json:"reason_digest"`
		TicketDigest        string            `json:"ticket_digest"`
		RequestedTTLSeconds int64             `json:"requested_ttl_seconds"`
		Deadline            string            `json:"deadline"`
		JTI                 string            `json:"jti"`
	}{value.Protocol, value.RequestID, value.RequesterID, value.TargetAgentID, value.Role, value.Purpose, value.BindingDigest, value.TenantID, value.Operation, value.ReasonDigest, value.TicketDigest, value.RequestedTTLSeconds, value.Deadline, value.JTI})
}

func approvalDigest(value Approval) string {
	return digest("sandbox-runtime/break-glass/approval/v1", struct {
		Protocol      string `json:"protocol"`
		RequestID     string `json:"request_id"`
		RequestDigest string `json:"request_digest"`
		Revision      int64  `json:"revision"`
		ApproverID    string `json:"approver_id"`
		Deadline      string `json:"deadline"`
		JTI           string `json:"jti"`
	}{value.Protocol, value.RequestID, value.RequestDigest, value.Revision, value.ApproverID, value.Deadline, value.JTI})
}
func commandDigest(value Command) string {
	return digest("sandbox-runtime/break-glass/command/v1", struct {
		Protocol  string `json:"protocol"`
		Type      string `json:"type"`
		RequestID string `json:"request_id"`
		Revision  int64  `json:"revision"`
		ActorID   string `json:"actor_id"`
		Deadline  string `json:"deadline"`
		JTI       string `json:"jti"`
	}{value.Protocol, value.Type, value.RequestID, value.Revision, value.ActorID, value.Deadline, value.JTI})
}
func capabilityDigest(value Capability) string {
	return digest("sandbox-runtime/break-glass/capability/v1", struct {
		Schema        string            `json:"schema"`
		CapabilityID  string            `json:"capability_id"`
		RequestID     string            `json:"request_id"`
		RequestDigest string            `json:"request_digest"`
		TargetAgentID string            `json:"target_agent_id"`
		Role          secretref.Role    `json:"role"`
		Purpose       secretref.Purpose `json:"purpose"`
		BindingDigest string            `json:"binding_digest"`
		TenantID      string            `json:"tenant_id"`
		Operation     string            `json:"operation"`
		IssuedAt      string            `json:"issued_at"`
		ExpiresAt     string            `json:"expires_at"`
		MaxUses       int               `json:"max_uses"`
		Revision      int64             `json:"revision"`
	}{value.Schema, value.CapabilityID, value.RequestID, value.RequestDigest, value.TargetAgentID, value.Role, value.Purpose, value.BindingDigest, value.TenantID, value.Operation, value.IssuedAt, value.ExpiresAt, value.MaxUses, value.Revision})
}
func consumeDigest(value Consume) string {
	return digest("sandbox-runtime/break-glass/consume/v1", struct {
		Protocol         string `json:"protocol"`
		CapabilityDigest string `json:"capability_digest"`
		TargetAgentID    string `json:"target_agent_id"`
		Deadline         string `json:"deadline"`
		JTI              string `json:"jti"`
	}{value.Protocol, value.Capability.Digest, value.TargetAgentID, value.Deadline, value.JTI})
}

func auditDigest(value AuditEntry) string {
	value.EntryHash = ""
	return digest("sandbox-runtime/break-glass/audit/v1", value)
}
func digest(domain string, value any) string {
	document, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append(append([]byte(nil), []byte(domain+"\x00")...), document...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func signDigest(key ed25519.PrivateKey, value string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(value)))
}
func verifyDigest(key ed25519.PublicKey, value, signature string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	return err == nil && len(key) == ed25519.PublicKeySize && len(decoded) == ed25519.SignatureSize && ed25519.Verify(key, []byte(value), decoded)
}

func validActorKind(value string) bool {
	return value == ActorRequester || value == ActorApprover || value == ActorOperator || value == ActorTarget
}
func validState(value string) bool {
	return value == StatePending || value == StateIssued || value == StateConsumed || value == StateRevoked || value == StateExpired
}
func validRole(role secretref.Role) bool {
	return role == secretref.RoleProduct || role == secretref.RoleProvider || role == secretref.RoleGateway || role == secretref.RoleGuest || role == secretref.RoleBrowser || role == secretref.RoleDesktop
}
func validPurpose(value secretref.Purpose) bool { return identifierPattern.MatchString(string(value)) }
func validTenant(value string) bool {
	return value == secretref.SystemTenant || tenantPattern.MatchString(value)
}
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return strings.HasPrefix(value, "sha256:") && value == strings.ToLower(value) && len(decoded) == sha256.Size && err == nil
}
func validJTI(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrDenied
	}
	return parsed, nil
}
func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

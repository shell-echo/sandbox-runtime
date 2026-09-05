// Package wire defines the implementation-neutral configuration and control
// protocol for the durable distributed revocation evidence processes.
package wire

const ProtocolVersion = 1

const (
	ActionOpen         = "open"
	ActionRoundTrip    = "round_trip"
	ActionExpectClosed = "expect_closed"
	ActionClose        = "close"
	ActionRevoke       = "revoke"
	ActionShutdown     = "shutdown"
)

const (
	OutcomeOpened     = "opened"
	OutcomeEchoed     = "echoed"
	OutcomeClosed     = "closed"
	OutcomeReleased   = "released"
	OutcomeRevoked    = "revoked"
	OutcomeTerminated = "terminated"
)

const (
	ErrorInvalidCommand        = "invalid_command"
	ErrorUnknownGateway        = "unknown_gateway"
	ErrorUnknownGrantBinding   = "unknown_grant_binding"
	ErrorConnectionExists      = "connection_exists"
	ErrorConnectionNotFound    = "connection_not_found"
	ErrorUpgradeFailed         = "upgrade_failed"
	ErrorNotUpgraded           = "not_upgraded"
	ErrorRoundTripFailed       = "round_trip_failed"
	ErrorCloseTimeout          = "close_timeout"
	ErrorCloseFailed           = "close_failed"
	ErrorRevocationUnavailable = "revocation_unavailable"
	ErrorControlLogUnavailable = "control_log_unavailable"
	ErrorInternal              = "internal"
)

type RevocationPolicy struct {
	MaxGrantLifetimeMillis int64 `json:"max_grant_lifetime_millis"`
	PollIntervalMillis     int64 `json:"poll_interval_millis"`
	OperationTimeoutMillis int64 `json:"operation_timeout_millis"`
}

type LocalCapacityPolicy struct {
	MaxTotal      int `json:"max_total"`
	MaxPerTenant  int `json:"max_per_tenant"`
	MaxPerSession int `json:"max_per_session"`
}

type ReconnectPolicy struct {
	MaxReconnects int   `json:"max_reconnects"`
	BackoffMillis int64 `json:"backoff_millis"`
}

type Principal struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	CallerID string `json:"caller_id"`
	TenantID string `json:"tenant_id"`
}

type Endpoint struct {
	ID                   string `json:"id"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
}

// GrantBinding is authoritative configuration supplied by the orchestrator.
// Its raw grant and absolute expiry never cross the JSONL control protocol.
type GrantBinding struct {
	ID          string `json:"id"`
	GrantID     string `json:"grant_id"`
	PrincipalID string `json:"principal_id"`
	EndpointID  string `json:"endpoint_id"`
	ExpiresAt   string `json:"expires_at"`
}

type GatewayConfig struct {
	Address               string              `json:"address"`
	ServerCertificateFile string              `json:"server_certificate_file"`
	ServerPrivateKeyFile  string              `json:"server_private_key_file"`
	RedisURL              string              `json:"redis_url"`
	RevocationNamespace   string              `json:"revocation_namespace"`
	RevocationPolicy      RevocationPolicy    `json:"revocation_policy"`
	AuditFile             string              `json:"audit_file"`
	ObservationFile       string              `json:"observation_file"`
	LocalCapacity         LocalCapacityPolicy `json:"local_capacity"`
	ReconnectPolicy       ReconnectPolicy     `json:"reconnect_policy"`
	Principals            []Principal         `json:"principals"`
	Endpoints             []Endpoint          `json:"endpoints"`
	GrantBindings         []GrantBinding      `json:"grant_bindings"`
}

type CallerConfig struct {
	CAFile        string            `json:"ca_file"`
	Gateways      map[string]string `json:"gateways"`
	Principals    []Principal       `json:"principals"`
	Endpoints     []Endpoint        `json:"endpoints"`
	GrantBindings []GrantBinding    `json:"grant_bindings"`
}

type RevokerConfig struct {
	RedisURL            string           `json:"redis_url"`
	RevocationNamespace string           `json:"revocation_namespace"`
	RevocationPolicy    RevocationPolicy `json:"revocation_policy"`
	ControlLogFile      string           `json:"control_log_file"`
	GrantBindings       []GrantBinding   `json:"grant_bindings"`
}

// Command contains only bounded logical names. Raw grants, grant expiry,
// credentials, endpoints, and backend configuration stay in process config.
type Command struct {
	Version        int    `json:"version"`
	Sequence       uint64 `json:"sequence"`
	Action         string `json:"action"`
	ConnectionID   string `json:"connection_id,omitempty"`
	GatewayID      string `json:"gateway_id,omitempty"`
	GrantBindingID string `json:"grant_binding_id,omitempty"`
	TimeoutMillis  int64  `json:"timeout_millis,omitempty"`
}

// Response deliberately contains no diagnostics or caller/backend identity.
type Response struct {
	Version   int    `json:"version"`
	Sequence  uint64 `json:"sequence"`
	OK        bool   `json:"ok"`
	Outcome   string `json:"outcome,omitempty"`
	Upgraded  bool   `json:"upgraded,omitempty"`
	CloseCode int    `json:"close_code,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type Scenario struct {
	Name             string        `json:"name"`
	Status           string        `json:"status"`
	DurationMillis   int64         `json:"duration_millis"`
	GatewayProcesses int           `json:"gateway_processes"`
	Measurements     []Measurement `json:"measurements,omitempty"`
}

type Measurement struct {
	GatewayID        string `json:"gateway_id"`
	AckToCloseMillis int64  `json:"ack_to_close_millis"`
}

type Report struct {
	EvidenceName string     `json:"evidence_name"`
	Scenarios    []Scenario `json:"scenarios"`
}

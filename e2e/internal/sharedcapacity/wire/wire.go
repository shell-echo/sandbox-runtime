// Package wire defines the implementation-neutral configuration and control
// protocol shared by the black-box caller and the Gateway fixture.
package wire

const ProtocolVersion = 1

const (
	ActionOpen         = "open"
	ActionRoundTrip    = "round_trip"
	ActionExpectClosed = "expect_closed"
	ActionClose        = "close"
	ActionShutdown     = "shutdown"
)

const (
	OutcomeOpened     = "opened"
	OutcomeEchoed     = "echoed"
	OutcomeClosed     = "closed"
	OutcomeReleased   = "released"
	OutcomeTerminated = "terminated"
)

type CapacityPolicy struct {
	MaxTotal                  int   `json:"max_total"`
	MaxPerTenant              int   `json:"max_per_tenant"`
	MaxPerSession             int   `json:"max_per_session"`
	LeaseTTLMillis            int64 `json:"lease_ttl_millis"`
	RenewIntervalMillis       int64 `json:"renew_interval_millis"`
	RenewalSafetyMarginMillis int64 `json:"renewal_safety_margin_millis"`
	OperationTimeoutMillis    int64 `json:"operation_timeout_millis"`
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

type GatewayConfig struct {
	Address               string         `json:"address"`
	ServerCertificateFile string         `json:"server_certificate_file"`
	ServerPrivateKeyFile  string         `json:"server_private_key_file"`
	RedisURL              string         `json:"redis_url"`
	CapacityNamespace     string         `json:"capacity_namespace"`
	AuditFile             string         `json:"audit_file"`
	ObservationFile       string         `json:"observation_file"`
	Policy                CapacityPolicy `json:"policy"`
	Principals            []Principal    `json:"principals"`
	Endpoints             []Endpoint     `json:"endpoints"`
}

type CallerConfig struct {
	CAFile     string            `json:"ca_file"`
	Gateways   map[string]string `json:"gateways"`
	Principals []Principal       `json:"principals"`
	Endpoints  []Endpoint        `json:"endpoints"`
}

// Command contains only bounded logical names. Raw identities and credentials
// remain in the caller's ephemeral configuration and never cross the control
// channel or enter evidence.
type Command struct {
	Version        int    `json:"version"`
	Sequence       uint64 `json:"sequence"`
	Action         string `json:"action"`
	ConnectionID   string `json:"connection_id,omitempty"`
	GatewayID      string `json:"gateway_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	EndpointID     string `json:"endpoint_id,omitempty"`
	GrantTTLMillis int64  `json:"grant_ttl_millis,omitempty"`
	TimeoutMillis  int64  `json:"timeout_millis,omitempty"`
}

// Response is intentionally diagnostic-free so URL queries, bearer tokens,
// handoff references, and backend errors cannot enter the evidence transcript.
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
	Name             string `json:"name"`
	Status           string `json:"status"`
	DurationMillis   int64  `json:"duration_millis"`
	GatewayProcesses int    `json:"gateway_processes"`
}

type Report struct {
	EvidenceName string     `json:"evidence_name"`
	Scenarios    []Scenario `json:"scenarios"`
}

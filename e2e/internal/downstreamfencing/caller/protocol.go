package caller

const ProtocolVersion = 1

const lockedCapabilityProfileID = "browser-v1"

const (
	ActionOpen         = "open"
	ActionCallCDP      = "call_cdp"
	ActionQueueCDP     = "queue_cdp"
	ActionReadCDP      = "read_cdp"
	ActionExpectClosed = "expect_closed"
	ActionClose        = "close"
	ActionShutdown     = "shutdown"
)

const (
	MessageText   = "text"
	MessageBinary = "binary"
)

const (
	OutcomeOpened     = "opened"
	OutcomeCompleted  = "completed"
	OutcomeWritten    = "written"
	OutcomeRead       = "read"
	OutcomeClosed     = "closed"
	OutcomeReleased   = "released"
	OutcomeTerminated = "terminated"
)

const (
	ErrorInvalidCommand      = "invalid_command"
	ErrorUnknownGateway      = "unknown_gateway"
	ErrorUnknownGrantBinding = "unknown_grant_binding"
	ErrorConnectionExists    = "connection_exists"
	ErrorConnectionNotFound  = "connection_not_found"
	ErrorConnectionCapacity  = "connection_capacity"
	ErrorUpgradeFailed       = "upgrade_failed"
	ErrorNotUpgraded         = "not_upgraded"
	ErrorWriteFailed         = "write_failed"
	ErrorReadFailed          = "read_failed"
	ErrorOperationTimeout    = "operation_timeout"
	ErrorOperationCanceled   = "operation_canceled"
	ErrorConnectionClosed    = "connection_closed"
	ErrorUnsafeResponse      = "unsafe_response"
	ErrorCloseTimeout        = "close_timeout"
	ErrorCloseFailed         = "close_failed"
	ErrorInternal            = "internal"
)

type Principal struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	CallerID string `json:"caller_id"`
	TenantID string `json:"tenant_id"`
}

// Endpoint is private orchestration material. It names no caller-visible
// network route and never crosses the JSONL control protocol.
type Endpoint struct {
	ID                   string `json:"id"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
}

// GrantBinding keeps the raw grant and absolute expiry outside the control
// protocol. Commands refer only to ID.
type GrantBinding struct {
	ID          string `json:"id"`
	GrantID     string `json:"grant_id"`
	PrincipalID string `json:"principal_id"`
	EndpointID  string `json:"endpoint_id"`
	ExpiresAt   string `json:"expires_at"`
}

type Config struct {
	CAFile        string            `json:"ca_file"`
	Gateways      map[string]string `json:"gateways"`
	Principals    []Principal       `json:"principals"`
	Endpoints     []Endpoint        `json:"endpoints"`
	GrantBindings []GrantBinding    `json:"grant_bindings"`
}

// Command exposes only logical connection and immutable binding names. CDP
// bytes use canonical base64 so text and binary WebSocket messages retain
// their complete-message boundary without turning the protocol into raw JSON.
type Command struct {
	Version        int    `json:"version"`
	Sequence       uint64 `json:"sequence"`
	Action         string `json:"action"`
	ConnectionID   string `json:"connection_id,omitempty"`
	GatewayID      string `json:"gateway_id,omitempty"`
	GrantBindingID string `json:"grant_binding_id,omitempty"`
	MessageType    string `json:"message_type,omitempty"`
	PayloadBase64  string `json:"payload_base64,omitempty"`
	TimeoutMillis  int64  `json:"timeout_millis,omitempty"`
}

// Response is a bounded projection. It never includes configuration or
// diagnostics. Message bytes are returned only after a private-material scan.
type Response struct {
	Version       int    `json:"version"`
	Sequence      uint64 `json:"sequence"`
	OK            bool   `json:"ok"`
	Outcome       string `json:"outcome,omitempty"`
	Upgraded      bool   `json:"upgraded,omitempty"`
	MessageType   string `json:"message_type,omitempty"`
	PayloadBase64 string `json:"payload_base64,omitempty"`
	CloseCode     int    `json:"close_code,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
}

package guestagent

// Observation is a private, optional Slice 6 component signal. It must never
// be sent over the Guest wire or used as an authorization decision. The
// consumer must enqueue it without I/O or blocking the Guest control path.
type Observation struct {
	Event             string
	AttemptDigest     string
	BindingGeneration int64
	Reason            string
}

type ObservationSink func(Observation)

const (
	ObservationGuestHelloWritten     = "guest_hello_written"
	ObservationGuestWelcomeAccepted  = "guest_welcome_accepted"
	ObservationGuestReadTerminated   = "guest_read_terminated"
	ObservationGuestAuthRetry        = "guest_auth_retry"
	ObservationProductAuthAccepted   = "product_auth_accepted"
	ObservationProductWelcomeWritten = "product_welcome_written"
	ObservationProductPeerInstalled  = "product_peer_installed"
	ObservationProductAuthorityStale = "product_authority_stale"
	ObservationProductCloseCompleted = "product_close_completed"
	// DependencyLost means the authority query failed; PostgreSQL attribution
	// requires the outer fault-injection evidence, not this callback alone.
	ObservationProductAuthorityDependencyLost = "product_authority_dependency_lost"
	ObservationProductDisconnectPending       = "product_disconnect_pending"
	ObservationProductDisconnectResolved      = "product_disconnect_resolved"
	ObservationProductAuthRetryable           = "product_auth_retryable"
)

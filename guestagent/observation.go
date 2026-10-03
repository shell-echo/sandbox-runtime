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
	ObservationProductAuthAccepted   = "product_auth_accepted"
	ObservationProductWelcomeWritten = "product_welcome_written"
	ObservationProductPeerInstalled  = "product_peer_installed"
	ObservationProductAuthorityStale = "product_authority_stale"
	ObservationProductCloseCompleted = "product_close_completed"
)

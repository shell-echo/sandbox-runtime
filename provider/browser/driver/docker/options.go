// Package docker provides a fail-closed Docker adapter for Provider-local
// Browser allocations. It is separate from the coding/shell lifecycle driver
// and does not compose Provider routes or a public Gateway.
package docker

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

const (
	BrowserRuntimeProfile = browserimage.ProfileID
	BrowserRelayPath      = "/usr/bin/socat"
	BrowserUser           = "1000:1000"

	maxBrowserAllocations = 1_000
	maxResourceBytes      = 64 << 30
	maxNanoCPUs           = 64_000_000_000
	maxPIDs               = 4_096
	maxTimeoutSeconds     = 600
)

var (
	ErrInvalidDriver      = errors.New("invalid Provider Browser Docker driver")
	ErrInvalidOptions     = errors.New("invalid Provider Browser Docker options")
	ErrInvalidProvenance  = errors.New("invalid Provider Browser image provenance")
	ErrNetworkUnavailable = errors.New("Provider Browser restricted network is unavailable")
	ErrOwnershipConflict  = errors.New("Provider Browser runtime ownership conflict")
	ErrInvalidRuntime     = errors.New("invalid Provider Browser runtime")

	privateValuePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	networkNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type PullPolicy string

const (
	PullNever        PullPolicy = "never"
	PullIfNotPresent PullPolicy = "if_not_present"
	PullAlways       PullPolicy = "always"
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Options struct {
	Host                     string
	Image                    string
	PullPolicy               PullPolicy
	MemoryBytes              int64
	NanoCPUs                 int64
	PidsLimit                int64
	InputsBytes              int64
	TmpfsBytes               int64
	WorkspaceBytes           int64
	OutputsBytes             int64
	OperationTimeoutSeconds  int
	ProvenanceTimeoutSeconds int
	PullTimeoutSeconds       int
	StopTimeoutSeconds       int
	DataRoot                 string
	ManifestPath             string
	SeccompPath              string
	Namespace                string
	ControllerID             string
	NetworkPolicyReference   string
	MaxSessionsPerSandbox    int
	MaxSessionsPerController int
	Clock                    Clock
}

type ProvenanceVerifier interface {
	Verify(context.Context, browserimage.Publication) error
}

// NetworkAttachment is adapter-private evidence returned by a mandatory
// restricted-egress provisioner. DockerName and LeaseID are never projected to
// Provider or Gateway clients.
type NetworkAttachment struct {
	DockerName      string
	LeaseID         string
	PolicyReference string
	EgressGateway   bool
	Public          bool
}

func (a NetworkAttachment) validate(expectedPolicy string) error {
	if !networkNamePattern.MatchString(a.DockerName) || !privateValuePattern.MatchString(a.LeaseID) ||
		a.PolicyReference != expectedPolicy || !a.EgressGateway || a.Public {
		return ErrNetworkUnavailable
	}
	switch a.DockerName {
	case "none", "host", "bridge", "default":
		return ErrNetworkUnavailable
	}
	return nil
}

type NetworkRequest struct {
	SandboxID        string
	BrowserSessionID string
	Namespace        string
	ControllerID     string
	PolicyReference  string
}

type RestrictedNetwork interface {
	Ready(context.Context, string) error
	// Acquire must be idempotent for the request identity. An error means no
	// lease was acquired; successful results must remain inspectable and
	// releasable after Provider process reconstruction.
	Acquire(context.Context, NetworkRequest) (NetworkAttachment, error)
	Inspect(context.Context, NetworkAttachment) error
	Release(context.Context, NetworkAttachment) error
}

func (o Options) validate() error {
	publication := browserimage.LockedPublication()
	if o.Image != publication.Image() {
		return fmt.Errorf("%w: image does not match the locked publication", ErrInvalidOptions)
	}
	switch o.PullPolicy {
	case PullNever, PullIfNotPresent, PullAlways:
	default:
		return fmt.Errorf("%w: unsupported pull policy", ErrInvalidOptions)
	}
	for _, value := range []int64{o.MemoryBytes, o.InputsBytes, o.TmpfsBytes, o.WorkspaceBytes, o.OutputsBytes} {
		if value <= 0 || value > maxResourceBytes {
			return fmt.Errorf("%w: invalid byte limit", ErrInvalidOptions)
		}
	}
	if o.InputsBytes > o.MemoryBytes || o.TmpfsBytes > o.MemoryBytes || o.WorkspaceBytes > o.MemoryBytes || o.OutputsBytes > o.MemoryBytes ||
		o.NanoCPUs <= 0 || o.NanoCPUs > maxNanoCPUs || o.PidsLimit <= 0 || o.PidsLimit > maxPIDs {
		return fmt.Errorf("%w: invalid resource limits", ErrInvalidOptions)
	}
	if o.OperationTimeoutSeconds <= 0 || o.OperationTimeoutSeconds > maxTimeoutSeconds ||
		o.ProvenanceTimeoutSeconds <= 0 || o.ProvenanceTimeoutSeconds > maxTimeoutSeconds ||
		o.PullTimeoutSeconds <= 0 || o.PullTimeoutSeconds > maxTimeoutSeconds ||
		o.StopTimeoutSeconds < 0 || o.StopTimeoutSeconds > maxTimeoutSeconds {
		return fmt.Errorf("%w: invalid timeouts", ErrInvalidOptions)
	}
	if strings.TrimSpace(o.DataRoot) == "" || !filepath.IsAbs(o.ManifestPath) || !filepath.IsAbs(o.SeccompPath) {
		return fmt.Errorf("%w: absolute state, manifest, and seccomp paths are required", ErrInvalidOptions)
	}
	if !privateValuePattern.MatchString(o.Namespace) || !privateValuePattern.MatchString(o.ControllerID) || !privateValuePattern.MatchString(o.NetworkPolicyReference) {
		return fmt.Errorf("%w: invalid ownership or network policy identity", ErrInvalidOptions)
	}
	if o.MaxSessionsPerSandbox != 1 ||
		o.MaxSessionsPerController < o.MaxSessionsPerSandbox || o.MaxSessionsPerController > maxBrowserAllocations || o.Clock == nil {
		return fmt.Errorf("%w: invalid capacity or clock", ErrInvalidOptions)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func allocationContextError(ctx context.Context, cause error) error {
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return contextError(ctx)
}

func allocationUnknown(ctx context.Context, cause error) error {
	if err := allocationContextError(ctx, cause); err != nil {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	return providerbrowser.ErrAllocationUnknown
}

func safeContextError(public error, ctx context.Context, cause error) error {
	if contextErr := allocationContextError(ctx, cause); contextErr != nil {
		return errors.Join(public, contextErr)
	}
	return public
}

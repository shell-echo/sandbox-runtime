// Package docker adapts the sealed Browser workload identity to the shared
// Provider restricted-egress Docker core.
package docker

import (
	"context"

	browserdriver "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
	restricteddocker "github.com/shell-echo/sandbox-runtime/provider/network/restricted/docker"
)

const (
	GatewayUser       = restricteddocker.GatewayUser
	GatewayEntrypoint = restricteddocker.GatewayEntrypoint
	GatewayComponent  = restricteddocker.GatewayComponent
	GatewayPath       = restricteddocker.GatewayPath
	UplinkRole        = restricteddocker.UplinkRole
)

var (
	ErrInvalidOptions     = restricteddocker.ErrInvalidOptions
	ErrPolicyUnavailable  = restricteddocker.ErrPolicyUnavailable
	ErrOwnershipConflict  = restricteddocker.ErrOwnershipConflict
	ErrNetworkUnavailable = restricteddocker.ErrNetworkUnavailable
	ErrOutcomeUnknown     = restricteddocker.ErrOutcomeUnknown
)

type Options struct {
	Host                    string
	GatewayImage            string
	UplinkNetwork           string
	Namespace               string
	ControllerID            string
	Policies                []gateway.Policy
	MemoryBytes             int64
	NanoCPUs                int64
	PidsLimit               int64
	OperationTimeoutSeconds int
	StopTimeoutSeconds      int
}

type Provisioner struct{ core *restricteddocker.Provisioner }

func New(ctx context.Context, options Options) (*Provisioner, error) {
	policies := make([]restricted.Policy, len(options.Policies))
	copy(policies, options.Policies)
	core, err := restricteddocker.NewBrowser(ctx, restricteddocker.Options{
		Host: options.Host, GatewayImage: options.GatewayImage, UplinkNetwork: options.UplinkNetwork,
		Namespace: options.Namespace, ControllerID: options.ControllerID, Policies: policies,
		MemoryBytes: options.MemoryBytes, NanoCPUs: options.NanoCPUs, PidsLimit: options.PidsLimit,
		OperationTimeoutSeconds: options.OperationTimeoutSeconds, StopTimeoutSeconds: options.StopTimeoutSeconds,
	})
	if err != nil {
		return nil, err
	}
	return &Provisioner{core: core}, nil
}

func (p *Provisioner) Ready(ctx context.Context, policy string) error {
	if p == nil || p.core == nil {
		return ErrNetworkUnavailable
	}
	return p.core.Ready(ctx, policy)
}

func (p *Provisioner) Acquire(ctx context.Context, request browserdriver.NetworkRequest) (browserdriver.NetworkAttachment, error) {
	if p == nil || p.core == nil {
		return browserdriver.NetworkAttachment{}, ErrNetworkUnavailable
	}
	attachment, err := p.core.Acquire(ctx, restricteddocker.Request{
		SandboxID: request.SandboxID, SessionID: request.BrowserSessionID, Namespace: request.Namespace,
		ControllerID: request.ControllerID, PolicyReference: request.PolicyReference,
		Generation: request.Generation, Fence: request.FencingToken,
	})
	return browserAttachment(attachment), err
}

func (p *Provisioner) Inspect(ctx context.Context, attachment browserdriver.NetworkAttachment) error {
	if p == nil || p.core == nil {
		return ErrNetworkUnavailable
	}
	return p.core.Inspect(ctx, coreAttachment(attachment))
}

func (p *Provisioner) Release(ctx context.Context, attachment browserdriver.NetworkAttachment) error {
	if p == nil || p.core == nil {
		return ErrNetworkUnavailable
	}
	return p.core.Release(ctx, coreAttachment(attachment))
}

func (p *Provisioner) Close() error {
	if p == nil || p.core == nil {
		return nil
	}
	return p.core.Close()
}

func browserAttachment(value restricteddocker.Attachment) browserdriver.NetworkAttachment {
	return browserdriver.NetworkAttachment{
		DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress,
		LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest,
		WorkloadIdentityDigest: value.WorkloadIdentityDigest, EgressGateway: value.EgressGateway, Public: value.Public,
	}
}

func coreAttachment(value browserdriver.NetworkAttachment) restricteddocker.Attachment {
	return restricteddocker.Attachment{
		DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress,
		LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest,
		WorkloadIdentityDigest: value.WorkloadIdentityDigest, EgressGateway: value.EgressGateway, Public: value.Public,
	}
}

var _ browserdriver.RestrictedNetwork = (*Provisioner)(nil)

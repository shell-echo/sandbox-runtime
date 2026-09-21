// Package docker adapts the sealed Desktop workload identity to the shared
// Provider restricted-egress Docker core.
package docker

import (
	"context"

	desktopdriver "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
	restricteddocker "github.com/shell-echo/sandbox-runtime/provider/network/restricted/docker"
)

type Options struct {
	Host                    string
	GatewayImage            string
	UplinkNetwork           string
	Namespace               string
	ControllerID            string
	Policies                []restricted.Policy
	MemoryBytes             int64
	NanoCPUs                int64
	PidsLimit               int64
	OperationTimeoutSeconds int
	StopTimeoutSeconds      int
}

type Provisioner struct{ core *restricteddocker.Provisioner }

func New(ctx context.Context, options Options) (*Provisioner, error) {
	core, err := restricteddocker.NewDesktop(ctx, restricteddocker.Options{
		Host: options.Host, GatewayImage: options.GatewayImage, UplinkNetwork: options.UplinkNetwork,
		Namespace: options.Namespace, ControllerID: options.ControllerID, Policies: append([]restricted.Policy(nil), options.Policies...),
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
		return restricteddocker.ErrNetworkUnavailable
	}
	return p.core.Ready(ctx, policy)
}

func (p *Provisioner) Acquire(ctx context.Context, request desktopdriver.NetworkRequest) (desktopdriver.NetworkAttachment, error) {
	if p == nil || p.core == nil {
		return desktopdriver.NetworkAttachment{}, restricteddocker.ErrNetworkUnavailable
	}
	attachment, err := p.core.Acquire(ctx, restricteddocker.Request{
		SandboxID: request.SandboxID, SessionID: request.DesktopSessionID, Namespace: request.Namespace,
		ControllerID: request.ControllerID, PolicyReference: request.PolicyReference,
		Generation: request.Generation, Fence: request.FencingToken,
	})
	return desktopAttachment(attachment), err
}

func (p *Provisioner) Inspect(ctx context.Context, attachment desktopdriver.NetworkAttachment) error {
	if p == nil || p.core == nil {
		return restricteddocker.ErrNetworkUnavailable
	}
	return p.core.Inspect(ctx, coreAttachment(attachment))
}

func (p *Provisioner) Release(ctx context.Context, attachment desktopdriver.NetworkAttachment) error {
	if p == nil || p.core == nil {
		return restricteddocker.ErrNetworkUnavailable
	}
	return p.core.Release(ctx, coreAttachment(attachment))
}

func (p *Provisioner) Close() error {
	if p == nil || p.core == nil {
		return nil
	}
	return p.core.Close()
}

func desktopAttachment(value restricteddocker.Attachment) desktopdriver.NetworkAttachment {
	return desktopdriver.NetworkAttachment{
		DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress,
		LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest,
		WorkloadIdentityDigest: value.WorkloadIdentityDigest, EgressGateway: value.EgressGateway, Public: value.Public,
	}
}

func coreAttachment(value desktopdriver.NetworkAttachment) restricteddocker.Attachment {
	return restricteddocker.Attachment{
		DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress,
		LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest,
		WorkloadIdentityDigest: value.WorkloadIdentityDigest, EgressGateway: value.EgressGateway, Public: value.Public,
	}
}

var _ desktopdriver.RestrictedNetwork = (*Provisioner)(nil)

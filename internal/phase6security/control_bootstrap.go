package phase6security

import (
	"slices"
	"sort"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
)

const ControlBootstrapProtocol = "sandbox-runtime.control-operator-bootstrap.v1"
const ControlDeliveryBootstrapProtocol = "sandbox-runtime.control-operator-bootstrap.v2"
const ControlSourceBootstrapProtocol = "sandbox-runtime.control-operator-bootstrap.v3"
const ControlTrustBootstrapProtocol = "sandbox-runtime.control-operator-bootstrap.v4"
const ControlTrustTarget = phase6fdloader.ControlTrustTarget
const ControlTrustObservationProtocol = "sandbox-runtime.control-trust-observation.v1"
const ControlSourceTarget = phase6fdloader.ControlSourceTarget
const ControlSourceObservationProtocol = "sandbox-runtime.control-source-observation.v1"
const ControlDeliveryTarget = phase6fdloader.ControlDeliveryTarget
const ControlDeliveryObservationProtocol = "sandbox-runtime.control-process-delivery.v1"
const ControlBootstrapTarget = "provider-docker-control-bootstrap-v1"
const ControlOperatorObservationProtocol = "sandbox-runtime.control-operator-observation.v1"

// A declaration within the single canonical Profile, never a trust anchor.
// The public key must ALSO match an independently provisioned executable pin.
// No private operator signing material is delivered to Control.
type ControlOperatorBootstrapV1 struct {
	Protocol              string                   `json:"protocol"`
	Target                string                   `json:"target"`
	KeyID                 string                   `json:"key_id"`
	KeyDigest             string                   `json:"key_digest"`
	PublicKeyFD           int                      `json:"public_key_fd"`
	PinSource             string                   `json:"pin_source"`
	ObservationProtocol   string                   `json:"observation_protocol"`
	MaxObservationSeconds int                      `json:"max_observation_seconds"`
	Launches              []ControlServiceLaunchV1 `json:"launches"`
}

type ControlServiceLaunchV1 struct {
	Deployment       string `json:"deployment"`
	Target           string `json:"target"`
	SourceRevision   string `json:"source_revision"`
	SourceTreeDigest string `json:"source_tree_digest"`
	ExecutableDigest string `json:"executable_digest"`
	LoaderDigest     string `json:"loader_digest,omitempty"`
	ProbeDigest      string `json:"probe_digest,omitempty"`
}

type ControlServiceIdentityV1 struct {
	Principal   Principal              `json:"principal"`
	Launch      ControlServiceLaunchV1 `json:"launch"`
	Entrypoint  []string               `json:"entrypoint"`
	Args        []string               `json:"args"`
	ProcessArgs []string               `json:"process_args"`
	Groups      []uint32               `json:"groups"`
}

type ControlBootstrapReview struct {
	Source             *ControlSourceReview       `json:"source,omitempty"`
	Admission          string                     `json:"admission"`
	ProfileBytesDigest string                     `json:"profile_bytes_digest"`
	ProfileDigest      string                     `json:"profile_digest"`
	Bootstrap          ControlOperatorBootstrapV1 `json:"bootstrap"`
	Services           []ControlServiceIdentityV1 `json:"services"`
}

func (p ProfileV2) controlServiceTargets() map[string]string {
	target := ControlBootstrapTarget
	if p.DockerControl.OperatorBootstrap != nil && p.DockerControl.OperatorBootstrap.Protocol == ControlDeliveryBootstrapProtocol {
		target = ControlDeliveryTarget
	}
	if p.DockerControl.OperatorBootstrap != nil && p.DockerControl.OperatorBootstrap.Protocol == ControlSourceBootstrapProtocol {
		target = ControlSourceTarget
	}
	if p.controlTrustDirectories() {
		target = ControlTrustTarget
	}
	targets := map[string]string{p.DockerControl.Deployment: target}
	for _, ep := range p.DockerControl.Endpoints {
		targets[ep.ProviderDeployment] = "core"
	}
	subjects := make(map[string]bool, len(targets))
	for n := range targets {
		subjects[n] = true
	}
	for _, agent := range p.TLSAgentBindings {
		if subjects[agent.SubjectDeployment] {
			targets[agent.AgentDeployment] = "workload-tls-agent"
		}
	}
	return targets
}
func (p ProfileV2) validateControlBootstrap() error {
	b := p.DockerControl.OperatorBootstrap
	if b == nil {
		return nil
	}
	versionOK := b.Protocol == ControlBootstrapProtocol && b.Target == ControlBootstrapTarget && b.ObservationProtocol == ControlOperatorObservationProtocol || b.Protocol == ControlDeliveryBootstrapProtocol && b.Target == ControlDeliveryTarget && b.ObservationProtocol == ControlDeliveryObservationProtocol
	versionOK = versionOK || b.Protocol == ControlSourceBootstrapProtocol && b.Target == ControlSourceTarget && b.ObservationProtocol == ControlSourceObservationProtocol
	versionOK = versionOK || b.Protocol == ControlTrustBootstrapProtocol && b.Target == ControlTrustTarget && b.ObservationProtocol == ControlTrustObservationProtocol
	if p.DockerControl.SourceAccess == nil || !versionOK || !namePattern.MatchString(b.KeyID) || !digestPattern.MatchString(b.KeyDigest) || b.PublicKeyFD != 3 || b.PinSource != "independently-provisioned-executable" || b.MaxObservationSeconds != 120 {
		return ErrInvalidProfile
	}
	wanted := p.controlServiceTargets()
	if len(wanted) != 8 || len(b.Launches) != len(wanted) {
		return ErrInvalidProfile
	}
	last := ""
	for _, l := range b.Launches {
		if wanted[l.Deployment] != l.Target || l.Deployment <= last || !slice6RevisionPattern.MatchString(l.SourceRevision) || len(l.SourceRevision) != 40 || !digestPattern.MatchString(l.SourceTreeDigest) || !digestPattern.MatchString(l.ExecutableDigest) {
			return ErrInvalidProfile
		}
		if l.Target == "core" {
			if l.LoaderDigest != "" {
				return ErrInvalidProfile
			}
		} else if !digestPattern.MatchString(l.LoaderDigest) {
			return ErrInvalidProfile
		}
		if l.Target == ControlDeliveryTarget || ControlObservesSource(l.Target) {
			if !digestPattern.MatchString(l.ProbeDigest) {
				return ErrInvalidProfile
			}
		} else if l.ProbeDigest != "" {
			return ErrInvalidProfile
		}
		last = l.Deployment
		delete(wanted, l.Deployment)
	}
	if len(wanted) != 0 {
		return ErrInvalidProfile
	}
	return nil
}

// ReviewControlBootstrap preserves complete-field validation and public holds.
// Image-layer/source hashes must be independently proved by the candidate gate;
// this description is not proof that the named executable exists or is running.
func ReviewControlBootstrap(document []byte) (ControlBootstrapReview, error) {
	boundary, e := reviewControlConsumerBoundary(document, true)
	if e != nil {
		return ControlBootstrapReview{}, e
	}
	p, e := decodeV2Canonical(document)
	if e != nil || p.DockerControl.OperatorBootstrap == nil || p.validateControlBootstrap() != nil {
		return ControlBootstrapReview{}, ErrInvalidProfile
	}
	out := ControlBootstrapReview{Admission: "held-not-a-permit", ProfileBytesDigest: boundary.ProfileBytesDigest, ProfileDigest: p.ProfileDigest, Bootstrap: *p.DockerControl.OperatorBootstrap}
	if ControlObservesSource(out.Bootstrap.Target) {
		r, err := ReviewControlSourceProfile(document)
		if err != nil {
			return ControlBootstrapReview{}, err
		}
		out.Source = &r
	}
	for _, l := range out.Bootstrap.Launches {
		var principal Principal
		for _, c := range p.Principals {
			if c.Name == l.Deployment {
				principal = c
			}
		}
		v := ControlServiceIdentityV1{Principal: principal, Launch: l, Entrypoint: []string{phase6fdloader.RolePath}, Args: []string{}, ProcessArgs: []string{phase6fdloader.RolePath}, Groups: []uint32{principal.GID}}
		if l.Target == "core" {
			v.Args = []string{"--config", Slice6PrivateConfigDirectory + "/" + Slice6StartupConfigFile, "provider", "serve"}
			v.ProcessArgs = append(v.ProcessArgs, v.Args...)
		} else {
			v.Entrypoint = []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}
		}
		if l.Deployment == p.DockerControl.Deployment {
			v.Groups = append(v.Groups, 0)
		}
		slices.Sort(v.Groups)
		out.Services = append(out.Services, v)
	}
	sort.Slice(out.Services, func(i, j int) bool { return out.Services[i].Principal.Name < out.Services[j].Principal.Name })
	return out, nil
}

func ControlObservesSource(target string) bool {
	return target == ControlSourceTarget || target == ControlTrustTarget
}

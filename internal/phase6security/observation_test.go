package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"testing"
)

func validObservations(profile Profile) ObservationSet {
	containers := make([]ContainerObservation, 0, len(profile.Principals))
	for _, principal := range profile.Principals {
		observation := ContainerObservation{DeploymentName: principal.Name, ContainerID: testDigest("container/" + principal.Name)[7:],
			PrincipalDigest: principal.PrincipalDigest, ControllingPrincipalDigest: principal.ControllingPrincipalDigest,
			ImageReference: principal.ImageReference, ImageDigest: principal.ImageDigest, ProcessUID: principal.UID, ProcessGID: principal.GID,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: append([]string(nil), principal.DroppedCapabilities...),
			SeccompDigest: principal.SeccompDigest, Resources: principal.Resources, Networks: append([]string(nil), principal.Networks...),
			Listeners: append([]Listener(nil), principal.Listeners...), RootWriteDenied: true, PrivilegeEscalationDenied: true,
			PIDExhaustionDenied: true, MemoryExhaustionDenied: true, CPUQuotaObserved: true, NamespaceIsolated: true,
			ExactCleanupObserved: true, DirectEgressDenied: principal.Kind != "egress_broker", ExternalUplinkObserved: principal.Kind == "egress_broker"}
		for _, mount := range principal.Mounts {
			observation.Mounts = append(observation.Mounts, ObservedMount{Target: mount.Target, Kind: mount.Kind,
				ReadOnly: mount.ReadOnly, MaxBytes: mount.MaxBytes})
		}
		containers = append(containers, observation)
	}
	containerIDs := make(map[string]string, len(containers))
	for _, observation := range containers {
		containerIDs[observation.DeploymentName] = observation.ContainerID
	}
	networks := make([]NetworkObservation, 0, len(profile.Networks))
	for index, network := range profile.Networks {
		observation := NetworkObservation{Name: network.Name, NetworkID: testDigest("network/" + network.Name)[7:],
			InspectDigest: testDigest("inspect/network/" + network.Name),
			Driver:        "bridge", Internal: network.Internal, GatewayModeIPv4: network.GatewayModeIPv4,
			Subnet: "172.20." + strconv.Itoa(index) + ".0/24"}
		if !network.Internal {
			observation.HostGateway = "172.20." + strconv.Itoa(index) + ".1"
		}
		for _, name := range network.Principals {
			observation.ContainerIDs = append(observation.ContainerIDs, containerIDs[name])
		}
		sort.Strings(observation.ContainerIDs)
		networks = append(networks, observation)
	}
	return ObservationSet{ProfileDigest: profile.ProfileDigest, Containers: containers, Networks: networks,
		DistinctContainerUIDGIDEstablished: true, ContainerNamespaceIsolationEstablished: true,
		HostUserNamespaceMappingEstablished: false, PlatformServiceAccountEstablished: false, SameHostLocalContainerGate: true}
}

func TestObservationsRequireExactMeasuredLeastPrivilege(t *testing.T) {
	profile := validProfile()
	observations := validObservations(profile)
	if err := ValidateObservations(profile, observations); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*ObservationSet){
		"profile mismatch":       func(o *ObservationSet) { o.ProfileDigest = testDigest("other") },
		"missing container":      func(o *ObservationSet) { o.Containers = o.Containers[1:] },
		"invalid container ID":   func(o *ObservationSet) { o.Containers[0].ContainerID = "container-name" },
		"duplicate container ID": func(o *ObservationSet) { o.Containers[1].ContainerID = o.Containers[0].ContainerID },
		"principal drift":        func(o *ObservationSet) { o.Containers[0].PrincipalDigest = testDigest("other") },
		"root process":           func(o *ObservationSet) { o.Containers[0].ProcessUID = 0 },
		"shared uid":             func(o *ObservationSet) { o.Containers[1].ProcessUID = o.Containers[0].ProcessUID },
		"writable root":          func(o *ObservationSet) { o.Containers[0].ReadOnlyRootFilesystem = false },
		"capability added":       func(o *ObservationSet) { o.Containers[0].AddedCapabilities = []string{"SYS_ADMIN"} },
		"seccomp drift":          func(o *ObservationSet) { o.Containers[0].SeccompDigest = testDigest("other") },
		"network drift":          func(o *ObservationSet) { o.Containers[0].Networks = append(o.Containers[0].Networks, "extra") },
		"proxy environment":      func(o *ObservationSet) { o.Containers[0].ProxyEnvironmentPresent = true },
		"privilege probe passed": func(o *ObservationSet) { o.Containers[0].PrivilegeEscalationDenied = false },
		"resource probe passed":  func(o *ObservationSet) { o.Containers[0].MemoryExhaustionDenied = false },
		"direct egress passed":   func(o *ObservationSet) { o.Containers[0].DirectEgressDenied = false },
		"platform overclaim":     func(o *ObservationSet) { o.PlatformServiceAccountEstablished = true },
		"host mapping overclaim": func(o *ObservationSet) { o.HostUserNamespaceMappingEstablished = true },
		"missing cleanup":        func(o *ObservationSet) { o.Containers[0].ExactCleanupObserved = false },
		"ordinary gateway": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Internal {
					o.Networks[index].GatewayModeIPv4 = "nat"
					break
				}
			}
		},
		"host bridge address": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Internal {
					o.Networks[index].HostGateway = "172.20.0.1"
					break
				}
			}
		},
		"IPv6 enabled":         func(o *ObservationSet) { o.Networks[0].IPv6Enabled = true },
		"network member drift": func(o *ObservationSet) { o.Networks[0].ContainerIDs[0] = testDigest("other")[7:] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := validObservations(profile)
			mutate(&candidate)
			if err := ValidateObservations(profile, candidate); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("ValidateObservations() error = %v", err)
			}
		})
	}
}

func TestDecodeObservationsRequiresClosedCanonicalDocument(t *testing.T) {
	profile := validProfile()
	document, err := json.Marshal(validObservations(profile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeObservations(document, profile); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"noncanonical": append([]byte(" "), document...),
		"trailing":     append(append([]byte(nil), document...), []byte("{}")...),
		"unknown":      bytes.Replace(document, []byte(`"profile_digest":`), []byte(`"extra":true,"profile_digest":`), 1),
		"duplicate":    bytes.Replace(document, []byte(`"profile_digest":`), []byte(`"profile_digest":"sha256:duplicate","profile_digest":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObservations(candidate, profile); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("DecodeObservations() error = %v", err)
			}
		})
	}
}

package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

func validObservations(profile Profile) ObservationSet {
	containers := make([]ContainerObservation, 0, len(profile.Principals))
	for _, principal := range profile.Principals {
		observation := ContainerObservation{DeploymentName: principal.Name, ContainerID: testDigest("container/" + principal.Name)[7:],
			PrincipalDigest: principal.PrincipalDigest, ControllingPrincipalDigest: principal.ControllingPrincipalDigest,
			ImageReference:             principal.ImageReference,
			RuntimeStoreImageID:        principal.ImageDigest,
			RuntimeStoreDescriptor:     ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: principal.ImageDigest, Size: 1234},
			SelectedManifestDescriptor: ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: principal.ImageDigest, Size: 1234},
			OCIConfigDigest:            principal.ImageConfigDigest,
			RuntimePlatform:            principal.ImagePlatform,
			ContainerInspectDigest:     testDigest("container-inspect/" + principal.Name),
			ImageInspectDigest:         testDigest("image-inspect/" + principal.Name),
			ProcessUID:                 principal.UID, ProcessGID: principal.GID,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: append([]string(nil), principal.DroppedCapabilities...),
			SeccompDigest: principal.SeccompDigest, Resources: principal.Resources, Networks: append([]string(nil), principal.Networks...),
			Listeners: append([]Listener(nil), principal.Listeners...), RootWriteDenied: true, PrivilegeEscalationDenied: true,
			PIDExhaustionDenied: true, MemoryExhaustionDenied: true, CPUQuotaObserved: true, NamespaceIsolated: true,
			ExactCleanupObserved: true, DirectEgressDenied: principal.Kind != "egress_broker" && principal.Kind != "ingress_relay",
			ExternalUplinkObserved: principal.Kind == "egress_broker" || principal.Kind == "ingress_relay"}
		if principal.ImageIdentityKind != ImageIdentityLocalConfig {
			observation.ImageDescriptorProofDigest = testDigest("descriptor-proof/" + principal.Name)
		}
		if principal.Name == "public-ingress-relay" {
			for _, binding := range profile.IngressBindings {
				frontend := netip.MustParseAddrPort(binding.FrontendAddress)
				host := netip.MustParseAddrPort(binding.HostBindAddress)
				observation.PublishedPorts = append(observation.PublishedPorts, PublishedPortObservation{
					Protocol: "tcp", ContainerPort: int(frontend.Port()), HostAddress: host.Addr().String(), HostPort: int(host.Port())})
			}
		}
		for _, mount := range principal.Mounts {
			observation.Mounts = append(observation.Mounts, ObservedMount{Target: mount.Target, Kind: mount.Kind,
				ReadOnly: mount.ReadOnly, MaxBytes: mount.MaxBytes, StorageID: mount.StorageID,
				PrivateFiles: mount.PrivateFiles})
		}
		containers = append(containers, observation)
	}
	containerIDs := make(map[string]string, len(containers))
	containerByName := make(map[string]ContainerObservation, len(containers))
	for _, observation := range containers {
		containerIDs[observation.DeploymentName] = observation.ContainerID
		containerByName[observation.DeploymentName] = observation
	}
	components := make([]ComponentObservation, 0, len(profile.Components))
	for _, component := range profile.Components {
		parent := containerByName[component.ParentDeployment]
		components = append(components, ComponentObservation{
			Name: component.Name, ParentDeployment: component.ParentDeployment, ParentContainerID: parent.ContainerID,
			ParentRuntimeStoreImageID: parent.RuntimeStoreImageID, PID: 1, ProcessStartTicks: 12345,
			ProcessUID: parent.ProcessUID, ProcessGID: parent.ProcessGID, Executable: component.Executable,
			ExecutableDigest: component.ExecutableDigest, Argv: append([]string(nil), component.Argv...),
			Socket: component.Socket, SocketMode: 0o600, BrokerProtocol: component.BrokerProtocol,
			SessionProtocol: component.SessionProtocol, ProcessInspectDigest: testDigest("proc/" + component.Name),
			SocketInspectDigest:      testDigest("socket/" + component.Name),
			SessionAssociationDigest: testDigest("session/" + component.Name),
		})
	}
	networks := make([]NetworkObservation, 0, len(profile.Networks))
	for _, network := range profile.Networks {
		subnet := network.IPv4Subnet
		prefix := netip.MustParsePrefix(subnet)
		observation := NetworkObservation{Name: network.Name, NetworkID: testDigest("network/" + network.Name)[7:],
			InspectDigest: testDigest("inspect/network/" + network.Name),
			Driver:        "bridge", Internal: network.Internal, GatewayModeIPv4: network.GatewayModeIPv4,
			Subnet: subnet}
		if !network.Internal {
			observation.HostGateway = prefix.Addr().Next().String()
		}
		for memberIndex, name := range network.Principals {
			address := prefix.Addr().Next().Next()
			for extra := 0; extra < memberIndex; extra++ {
				address = address.Next()
			}
			if network.Name == "gateway-internal" || network.Name == "product-internal" ||
				network.Name == "provider-browser-internal" || network.Name == "provider-desktop-internal" {
				if strings.HasPrefix(name, "egress-broker-") {
					address = prefix.Addr().Next().Next().Next()
				} else {
					address = prefix.Addr().Next().Next()
				}
			}
			if network.Name == "ingress-gateway" || network.Name == "ingress-product" {
				if name == "public-ingress-relay" {
					address = prefix.Addr().Next().Next()
				} else {
					address = prefix.Addr().Next().Next().Next()
				}
			}
			observation.Endpoints = append(observation.Endpoints,
				NetworkEndpointObservation{ContainerID: containerIDs[name], IPv4Address: address.String()})
			observation.ContainerIDs = append(observation.ContainerIDs, containerIDs[name])
		}
		sort.Strings(observation.ContainerIDs)
		sort.Slice(observation.Endpoints, func(i, j int) bool {
			return observation.Endpoints[i].ContainerID < observation.Endpoints[j].ContainerID
		})
		networks = append(networks, observation)
	}
	return ObservationSet{ProfileDigest: profile.ProfileDigest, Containers: containers, Components: components, Networks: networks,
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
		"profile mismatch":        func(o *ObservationSet) { o.ProfileDigest = testDigest("other") },
		"missing container":       func(o *ObservationSet) { o.Containers = o.Containers[1:] },
		"missing broker process":  func(o *ObservationSet) { o.Components = nil },
		"broker fake container":   func(o *ObservationSet) { o.Components[0].ParentContainerID = testDigest("fake-broker-container")[7:] },
		"broker wrong uid":        func(o *ObservationSet) { o.Components[0].ProcessUID++ },
		"broker pid reuse":        func(o *ObservationSet) { o.Components[0].ProcessStartTicks = 0 },
		"broker executable drift": func(o *ObservationSet) { o.Components[0].ExecutableDigest = testDigest("other") },
		"broker socket drift":     func(o *ObservationSet) { o.Components[0].SocketMode = 0o666 },
		"broker session unbound":  func(o *ObservationSet) { o.Components[0].SessionAssociationDigest = "" },
		"invalid container ID":    func(o *ObservationSet) { o.Containers[0].ContainerID = "container-name" },
		"duplicate container ID":  func(o *ObservationSet) { o.Containers[1].ContainerID = o.Containers[0].ContainerID },
		"principal drift":         func(o *ObservationSet) { o.Containers[0].PrincipalDigest = testDigest("other") },
		"root process":            func(o *ObservationSet) { o.Containers[0].ProcessUID = 0 },
		"shared uid":              func(o *ObservationSet) { o.Containers[1].ProcessUID = o.Containers[0].ProcessUID },
		"writable root":           func(o *ObservationSet) { o.Containers[0].ReadOnlyRootFilesystem = false },
		"capability added":        func(o *ObservationSet) { o.Containers[0].AddedCapabilities = []string{"SYS_ADMIN"} },
		"seccomp drift":           func(o *ObservationSet) { o.Containers[0].SeccompDigest = testDigest("other") },
		"network drift":           func(o *ObservationSet) { o.Containers[0].Networks = append(o.Containers[0].Networks, "extra") },
		"proxy environment":       func(o *ObservationSet) { o.Containers[0].ProxyEnvironmentPresent = true },
		"privilege probe passed":  func(o *ObservationSet) { o.Containers[0].PrivilegeEscalationDenied = false },
		"resource probe passed":   func(o *ObservationSet) { o.Containers[0].MemoryExhaustionDenied = false },
		"direct egress passed":    func(o *ObservationSet) { o.Containers[0].DirectEgressDenied = false },
		"platform overclaim":      func(o *ObservationSet) { o.PlatformServiceAccountEstablished = true },
		"host mapping overclaim":  func(o *ObservationSet) { o.HostUserNamespaceMappingEstablished = true },
		"missing cleanup":         func(o *ObservationSet) { o.Containers[0].ExactCleanupObserved = false },
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
		"target host publication": func(o *ObservationSet) {
			for index := range o.Containers {
				if o.Containers[index].DeploymentName == "gateway-runtime" {
					o.Containers[index].PublishedPorts = []PublishedPortObservation{{Protocol: "tcp", ContainerPort: 8445,
						HostAddress: "127.0.0.1", HostPort: 18445}}
				}
			}
		},
		"relay extra publication": func(o *ObservationSet) {
			for index := range o.Containers {
				if o.Containers[index].DeploymentName == "public-ingress-relay" {
					o.Containers[index].PublishedPorts = append(o.Containers[index].PublishedPorts,
						PublishedPortObservation{Protocol: "tcp", ContainerPort: 1080, HostAddress: "127.0.0.1", HostPort: 11080})
				}
			}
		},
		"relay published host drift": func(o *ObservationSet) {
			for index := range o.Containers {
				if o.Containers[index].DeploymentName == "public-ingress-relay" {
					o.Containers[index].PublishedPorts[0].HostAddress = "0.0.0.0"
				}
			}
		},
		"relay frontend IP drift": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Name == "public-ingress" {
					o.Networks[index].Endpoints[0].IPv4Address = "10.11.0.4"
				}
			}
		},
		"target endpoint IP drift": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Name == "ingress-product" {
					for member := range o.Networks[index].Endpoints {
						if o.Networks[index].Endpoints[member].ContainerID == testDigest("container/product-runtime")[7:] {
							o.Networks[index].Endpoints[member].IPv4Address = "10.13.0.4"
						}
					}
				}
			}
		},
		"broker target IP drift": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Name == "gateway-internal" {
					for member := range o.Networks[index].Endpoints {
						if o.Networks[index].Endpoints[member].ContainerID == testDigest("container/egress-broker-gateway")[7:] {
							o.Networks[index].Endpoints[member].IPv4Address = "10.27.0.4"
						}
					}
				}
			}
		},
		"duplicate endpoint IP": func(o *ObservationSet) {
			for index := range o.Networks {
				if o.Networks[index].Name == "ingress-gateway" {
					o.Networks[index].Endpoints[1].IPv4Address = o.Networks[index].Endpoints[0].IPv4Address
				}
			}
		},
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

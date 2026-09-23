package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// DockerPortObservation is a bounded projection of one raw `docker inspect`
// receipt. The raw bytes remain the evidence identified by InspectDigest.
type DockerPortObservation struct {
	ContainerID   string                     `json:"container_id"`
	InspectDigest string                     `json:"inspect_digest"`
	Ports         []PublishedPortObservation `json:"ports"`
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func ObserveDockerPorts(document []byte, profile Profile, deployment string) (DockerPortObservation, error) {
	if len(document) < 1 || len(document) > maxBytes || rejectDuplicateMembers(document) != nil || profile.Validate() != nil {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	known := false
	for _, principal := range profile.Principals {
		if principal.Name == deployment {
			known = true
			break
		}
	}
	if !known {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	var values []struct {
		ID         string `json:"Id"`
		HostConfig struct {
			PublishAllPorts bool
			PortBindings    map[string][]dockerPortBinding
		}
		NetworkSettings struct {
			Ports map[string][]dockerPortBinding
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	if decoder.Decode(&values) != nil || len(values) != 1 {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	value := values[0]
	if !containerIDPattern.MatchString(value.ID) || value.HostConfig.PublishAllPorts {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	expected := []PublishedPortObservation{}
	if deployment == "public-ingress-relay" {
		for _, binding := range profile.IngressBindings {
			frontend, frontendErr := netip.ParseAddrPort(binding.FrontendAddress)
			host, hostErr := netip.ParseAddrPort(binding.HostBindAddress)
			if frontendErr != nil || hostErr != nil {
				return DockerPortObservation{}, ErrInvalidObservation
			}
			expected = append(expected, PublishedPortObservation{Protocol: "tcp", ContainerPort: int(frontend.Port()),
				HostAddress: host.Addr().String(), HostPort: int(host.Port())})
		}
	}
	if len(value.HostConfig.PortBindings) != len(expected) || len(value.NetworkSettings.Ports) != len(expected) {
		return DockerPortObservation{}, ErrInvalidObservation
	}
	for _, port := range expected {
		key := strconv.Itoa(port.ContainerPort) + "/" + port.Protocol
		declared, declaredOK := value.HostConfig.PortBindings[key]
		active, activeOK := value.NetworkSettings.Ports[key]
		if !declaredOK || !activeOK || len(declared) != 1 || len(active) != 1 ||
			declared[0] != (dockerPortBinding{HostIP: port.HostAddress, HostPort: strconv.Itoa(port.HostPort)}) ||
			active[0] != declared[0] {
			return DockerPortObservation{}, ErrInvalidObservation
		}
	}
	digest := sha256.Sum256(document)
	return DockerPortObservation{ContainerID: value.ID, InspectDigest: "sha256:" + hex.EncodeToString(digest[:]), Ports: expected}, nil
}

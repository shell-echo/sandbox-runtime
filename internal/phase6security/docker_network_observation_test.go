package phase6security

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObserveDockerNetworkRejectsInspectDrift(t *testing.T) {
	profile := validProfile()
	var expected Network
	for _, network := range profile.Networks {
		if network.Kind == "role_internal" {
			expected = network
			break
		}
	}
	IDs := map[string]string{}
	for _, name := range expected.Principals {
		IDs[name] = testDigest("container/" + name)[7:]
	}
	valid := func() map[string]any {
		members := map[string]any{}
		for _, ID := range IDs {
			members[ID] = map[string]any{"Name": "opaque"}
		}
		return map[string]any{
			"Name": expected.Name, "Id": testDigest("network/" + expected.Name)[7:], "Driver": "bridge",
			"Scope": "local", "Internal": true, "Attachable": false, "Ingress": false,
			"EnableIPv4": true, "EnableIPv6": false,
			"Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
				"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"},
			"IPAM":       map[string]any{"Config": []map[string]string{{"Subnet": "172.20.0.0/24", "Gateway": ""}}},
			"Containers": members,
		}
	}
	encode := func(value map[string]any) []byte {
		t.Helper()
		document, err := json.Marshal([]any{value})
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	if observation, err := ObserveDockerNetwork(encode(valid()), expected, IDs); err != nil ||
		observation.GatewayModeIPv4 != "isolated" || observation.HostGateway != "" || len(observation.ContainerIDs) != len(IDs) {
		t.Fatalf("valid inspect = %#v, %v", observation, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"ordinary gateway": func(value map[string]any) {
			value["Options"].(map[string]string)["com.docker.network.bridge.gateway_mode_ipv4"] = "nat"
		},
		"host address": func(value map[string]any) {
			value["IPAM"].(map[string]any)["Config"].([]map[string]string)[0]["Gateway"] = "172.20.0.1"
		},
		"IPv6": func(value map[string]any) { value["EnableIPv6"] = true },
		"unrecognized option": func(value map[string]any) {
			value["Options"].(map[string]string)["com.docker.network.bridge.trusted_host_interfaces"] = "eth0"
		},
		"extra member": func(value map[string]any) {
			value["Containers"].(map[string]any)[testDigest("extra")[7:]] = map[string]any{}
		},
		"wrong member": func(value map[string]any) {
			for ID := range value["Containers"].(map[string]any) {
				delete(value["Containers"].(map[string]any), ID)
				break
			}
		},
		"bad subnet": func(value map[string]any) {
			value["IPAM"].(map[string]any)["Config"].([]map[string]string)[0]["Subnet"] = "172.20.0.1/24"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(candidate)
			if _, err := ObserveDockerNetwork(encode(candidate), expected, IDs); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("ObserveDockerNetwork() error = %v", err)
			}
		})
	}
}

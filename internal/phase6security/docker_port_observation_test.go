package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"testing"
)

func TestObserveDockerPortsRequiresExactRelayOnlyPublication(t *testing.T) {
	profile := validProfile()
	containerID := testDigest("container/public-ingress-relay")[7:]
	valid := func() map[string]any {
		declared, active := map[string]any{}, map[string]any{}
		for _, binding := range profile.IngressBindings {
			frontend := netip.MustParseAddrPort(binding.FrontendAddress)
			host := netip.MustParseAddrPort(binding.HostBindAddress)
			key := strconv.Itoa(int(frontend.Port())) + "/tcp"
			declared[key] = []any{map[string]any{
				"HostIp": host.Addr().String(), "HostPort": strconv.Itoa(int(host.Port()))}}
			active[key] = []any{map[string]any{
				"HostIp": host.Addr().String(), "HostPort": strconv.Itoa(int(host.Port()))}}
		}
		return map[string]any{"Id": containerID,
			"HostConfig":      map[string]any{"PublishAllPorts": false, "PortBindings": declared},
			"NetworkSettings": map[string]any{"Ports": active}}
	}
	encode := func(value map[string]any) []byte {
		t.Helper()
		document, err := json.Marshal([]any{value})
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	observed, err := ObserveDockerPorts(encode(valid()), profile, "public-ingress-relay")
	if err != nil || observed.ContainerID != containerID || len(observed.Ports) != 2 ||
		!digestPattern.MatchString(observed.InspectDigest) {
		t.Fatalf("valid relay publication = %#v, %v", observed, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"publish all": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["PublishAllPorts"] = true
		},
		"extra declaration": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["PortBindings"].(map[string]any)["1080/tcp"] = []any{}
		},
		"missing active port": func(value map[string]any) {
			delete(value["NetworkSettings"].(map[string]any)["Ports"].(map[string]any), "8445/tcp")
		},
		"wrong host": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["PortBindings"].(map[string]any)["8445/tcp"] =
				[]any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "18445"}}
		},
		"wrong active mapping": func(value map[string]any) {
			value["NetworkSettings"].(map[string]any)["Ports"].(map[string]any)["8445/tcp"] =
				[]any{map[string]any{"HostIp": "127.0.0.1", "HostPort": "9999"}}
		},
		"unrecognized protocol": func(value map[string]any) {
			value["NetworkSettings"].(map[string]any)["Ports"].(map[string]any)["8445/udp"] = []any{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(candidate)
			if _, err := ObserveDockerPorts(encode(candidate), profile, "public-ingress-relay"); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("publication drift accepted: %v", err)
			}
		})
	}
	for _, candidate := range [][]byte{
		bytes.Replace(encode(valid()), []byte(`"Id":`), []byte(`"Id":"duplicate","Id":`), 1),
		append(encode(valid()), []byte(`{}`)...),
	} {
		if _, err := ObserveDockerPorts(candidate, profile, "public-ingress-relay"); !errors.Is(err, ErrInvalidObservation) {
			t.Fatalf("noncanonical inspect accepted: %v", err)
		}
	}
	if _, err := ObserveDockerPorts(encode(valid()), profile, "gateway-runtime"); !errors.Is(err, ErrInvalidObservation) {
		t.Fatal("Gateway accepted relay host publication")
	}
	target := valid()
	target["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{}
	target["NetworkSettings"].(map[string]any)["Ports"] = map[string]any{}
	if _, err := ObserveDockerPorts(encode(target), profile, "gateway-runtime"); err != nil {
		t.Fatalf("unpublished Gateway rejected: %v", err)
	}
}

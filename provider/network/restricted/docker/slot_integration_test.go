//go:build integration

package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

// TestGatewayReservedSlotDocker is a real Docker component test. It proves
// the gateway's effective Docker user, restart-safe ownership reconstruction,
// collision rejection and exact cleanup; it is not a Provider DB reservation
// or the complete Phase 6 deployment gate.
func TestGatewayReservedSlotDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_GATEWAY_SLOT_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_GATEWAY_SLOT_INTEGRATION=1")
	}
	image := os.Getenv("SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE")
	if !immutableImage.MatchString(image) {
		t.Fatal("set SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE to an immutable local image ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if _, err := api.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 8)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(tokenBytes)
	namespace := "gateway-slot-" + token
	uplink := "sr-gateway-slot-uplink-" + token
	_, err = api.NetworkCreate(ctx, uplink, client.NetworkCreateOptions{Driver: "bridge", Labels: map[string]string{
		managedLabel: "true", ownerLabel: UplinkRole, namespaceLabel: namespace,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := api.NetworkRemove(cleanup, uplink, client.NetworkRemoveOptions{}); err != nil {
			t.Errorf("remove exact test uplink: %v", err)
		}
	}()
	options := Options{GatewayImage: image, UplinkNetwork: uplink, Namespace: namespace,
		ControllerID: "controller-" + token, Policies: []restricted.Policy{{Reference: "policy-" + token,
			AllowedHosts: []string{"allowed.test"}}}, MemoryBytes: 128 << 20, NanoCPUs: 500_000_000,
		PidsLimit: 64, OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10}
	provisioner, err := NewBrowser(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer provisioner.Close()
	request := Request{SandboxID: "sandbox-" + token, SessionID: "browser-" + token,
		Namespace: namespace, ControllerID: options.ControllerID, PolicyReference: options.Policies[0].Reference,
		Generation: 1, Fence: 1, Slot: sandboxidentity.Slot{ID: "slot-1", WorkloadUID: 20000,
			WorkloadGID: 30000, GatewayUID: 20001, GatewayGID: 30001}}
	expected, _, _, err := provisioner.desired(request, options.Policies[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := provisioner.Release(cleanup, expected); err != nil {
			t.Errorf("release exact gateway slot: %v", err)
		}
	}()
	attachment, err := provisioner.Acquire(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if attachment != expected {
		t.Fatalf("gateway attachment drift: %#v != %#v", attachment, expected)
	}
	observed, err := api.ContainerInspect(ctx, attachment.GatewayContainer, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Container.Config == nil || observed.Container.State == nil ||
		observed.Container.Config.User != "20001:30001" || !observed.Container.State.Running {
		t.Fatalf("gateway user/running drift: %#v", observed.Container)
	}
	processes, err := api.ContainerTop(ctx, attachment.GatewayContainer, client.ContainerTopOptions{})
	if err != nil {
		t.Fatal(err)
	}
	uidColumn := slices.Index(processes.Titles, "UID")
	commandColumn := slices.Index(processes.Titles, "CMD")
	if uidColumn < 0 || commandColumn < 0 || len(processes.Processes) != 1 ||
		len(processes.Processes[0]) != len(processes.Titles) ||
		processes.Processes[0][uidColumn] != "20001" ||
		processes.Processes[0][commandColumn] != GatewayEntrypoint+" serve" {
		t.Fatalf("effective gateway process identity = columns %v, rows %v", processes.Titles, processes.Processes)
	}
	groups, err := api.ContainerTop(ctx, attachment.GatewayContainer, client.ContainerTopOptions{Arguments: []string{"-o", "uid,gid,pid,args"}})
	if err != nil {
		t.Fatal(err)
	}
	groupUID, groupGID := slices.Index(groups.Titles, "UID"), slices.Index(groups.Titles, "GID")
	if groupUID < 0 || groupGID < 0 || len(groups.Processes) != 1 ||
		len(groups.Processes[0]) != len(groups.Titles) ||
		groups.Processes[0][groupUID] != "20001" || groups.Processes[0][groupGID] != "30001" {
		t.Fatalf("effective gateway UID/GID = columns %v, rows %v", groups.Titles, groups.Processes)
	}
	if replay, err := provisioner.Acquire(ctx, request); err != nil || replay != attachment {
		t.Fatalf("exact slot replay = %#v, %v", replay, err)
	}
	changed := request
	changed.Slot.GatewayUID++
	if _, err := provisioner.Acquire(ctx, changed); err != ErrOwnershipConflict {
		t.Fatalf("cross-slot collision = %v", err)
	}
	if err := provisioner.Release(ctx, attachment); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Absent(ctx, attachment); err != nil {
		t.Fatalf("post-release Docker absence: %v", err)
	}
	if _, err := api.ContainerInspect(ctx, attachment.GatewayContainer, client.ContainerInspectOptions{}); err == nil {
		t.Fatal("gateway container remains after release")
	}
	if _, err := api.NetworkInspect(ctx, attachment.DockerName, client.NetworkInspectOptions{}); err == nil {
		t.Fatal("internal network remains after release")
	}
}

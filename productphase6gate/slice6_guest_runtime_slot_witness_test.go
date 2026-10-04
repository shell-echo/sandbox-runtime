//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSlice6GuestRuntimeWitnessSlotNamesFailClosed(t *testing.T) {
	runID := strings.Repeat("a", 32)
	id := strings.Repeat("b", 64)
	a, err := slice6GuestRuntimeNameForSlot(runID, "guest-a")
	if err != nil || a != "sr-p6-guest-runtime-"+runID {
		t.Fatal("original Guest name drift")
	}
	b, err := slice6GuestRuntimeNameForSlot(runID, "guest-b")
	if err != nil || b != "sr-p6-guest-runtime-b-"+runID || a == b {
		t.Fatal("replacement Guest name drift")
	}
	for _, slot := range []string{"", "guest", "guest-c", "product-b", "Guest-B"} {
		if _, err := slice6GuestRuntimeNameForSlot(runID, slot); err == nil {
			t.Fatal("unreviewed Guest slot received a container name")
		}
	}
	if _, err := slice6GuestRuntimeNameForSlot("not-a-run", "guest-a"); err == nil {
		t.Fatal("invalid run received a Guest container name")
	}
	for _, test := range []struct {
		name, slot string
		allow      bool
	}{
		{"/" + a, "guest-a", true}, {"/" + b, "guest-b", true},
		{"/" + a, "guest-b", false}, {"/" + b, "guest-a", false},
		{"/other", "guest-a", false},
	} {
		member := slice6ProductRuntimeInspect{ID: id, Name: test.name}
		member.Config.Labels = map[string]string{slice6RunLabel: runID}
		member.State.Running, member.State.Pid = true, 123
		if slice6GuestRuntimeMemberMatchesSlot(runID, id, test.slot, member) != test.allow {
			t.Fatalf("Guest slot/member acceptance drift: %s %s", test.name, test.slot)
		}
		if test.allow {
			for _, mutate := range []func(*slice6ProductRuntimeInspect){
				func(value *slice6ProductRuntimeInspect) { value.ID = strings.Repeat("c", 64) },
				func(value *slice6ProductRuntimeInspect) {
					value.Config.Labels[slice6RunLabel] = strings.Repeat("c", 32)
				},
				func(value *slice6ProductRuntimeInspect) { value.State.Running = false },
				func(value *slice6ProductRuntimeInspect) { value.State.OOMKilled = true },
				func(value *slice6ProductRuntimeInspect) { value.State.Pid = 0 },
				func(value *slice6ProductRuntimeInspect) { value.RestartCount = 1 },
			} {
				wrong := member
				wrong.Config.Labels = map[string]string{slice6RunLabel: runID}
				mutate(&wrong)
				if slice6GuestRuntimeMemberMatchesSlot(runID, id, test.slot, wrong) {
					t.Fatal("Guest witness accepted identity or PID drift")
				}
			}
		}
	}
}

func TestSlice6GuestRuntimeWitnessABNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_AB_WITNESS_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_AB_WITNESS_NO_ISSUER=1 for exact Docker A/B witness")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Guest A/B witness exact Docker cleanup: %v", err)
		}
	})
	plan := slice6GuestRuntimeLaunchPlan{}
	createNetwork := func(label string) (string, string, string) {
		t.Helper()
		name := "sr-p6-guest-witness-" + label + "-" + run.id
		output, err := run.docker(ctx, "network", "create", "--internal", "--driver", "bridge",
			"--label", run.label(), name)
		id := strings.TrimSpace(string(output))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("Guest witness network creation unavailable")
		}
		subnetRaw, err := run.docker(ctx, "network", "inspect", "--format",
			"{{(index .IPAM.Config 0).Subnet}}", id)
		subnet, parseErr := netip.ParsePrefix(strings.TrimSpace(string(subnetRaw)))
		if err != nil || parseErr != nil || !subnet.Addr().Is4() {
			t.Fatal("Guest witness network subnet unavailable")
		}
		ip := subnet.Masked().Addr()
		for range 20 {
			ip = ip.Next()
		}
		if !subnet.Contains(ip) || !ip.Is4() {
			t.Fatal("Guest witness static IP outside exact network")
		}
		return id, name, ip.String()
	}
	productID, productName, productIP := createNetwork("product")
	internalID, internalName, internalIP := createNetwork("runtime")
	plan.ProductNetwork.Name, plan.ProductIP = productName, productIP
	plan.InternalNetwork.Name, plan.InternalIP = internalName, internalIP
	for _, slot := range []string{"guest-a", "guest-b"} {
		name, err := slice6GuestRuntimeNameForSlot(run.id, slot)
		if err != nil {
			t.Fatal(err)
		}
		output, err := run.docker(ctx, "create", "--pull=never", "--name", name,
			"--label", run.label(), "--log-driver=none", "--network", productID,
			"--ip", productIP, "--restart=no", "--user=65532:65532", "--read-only",
			"--cap-drop=ALL", "--security-opt=no-new-privileges:true",
			"--memory=67108864", "--cpus=0.2", "--pids-limit=16",
			"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec", "sleep 60")
		id := strings.TrimSpace(string(output))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("Guest witness exact PID1 create unavailable")
		}
		if _, err := run.docker(ctx, "network", "connect", "--ip", internalIP, internalID, id); err != nil {
			t.Fatal("Guest witness second network attach unavailable")
		}
		if _, err := run.docker(ctx, "start", id); err != nil {
			t.Fatal("Guest witness exact PID1 start unavailable")
		}
		if err := slice6VerifyGuestRuntimeRunningNetworksForSlot(ctx, run, id,
			plan, productID, internalID, slot); err != nil {
			t.Fatalf("exact %s two-network witness unavailable: %v", slot, err)
		}
		legacy := slice6VerifyGuestRuntimeRunningNetworks(ctx, run, id,
			plan, productID, internalID)
		if (slot == "guest-a" && legacy != nil) || (slot == "guest-b" && legacy == nil) {
			t.Fatal("historical component witness did not remain Guest-A-only")
		}
		other := "guest-a"
		if slot == other {
			other = "guest-b"
		}
		if slice6VerifyGuestRuntimeRunningNetworksForSlot(ctx, run, id,
			plan, productID, internalID, other) == nil ||
			slice6VerifyGuestRuntimeRunningNetworksForSlot(ctx, run, id,
				plan, internalID, productID, slot) == nil {
			t.Fatal("Guest witness accepted opposite slot or swapped networks")
		}
		wrongIP := plan
		wrongIP.ProductIP = internalIP
		if slice6VerifyGuestRuntimeRunningNetworksForSlot(ctx, run, id,
			wrongIP, productID, internalID, slot) == nil {
			t.Fatal("Guest witness accepted wrong product IP")
		}
		if _, err := run.docker(ctx, "rm", "-f", "-v", id); err != nil {
			t.Fatal("Guest witness exact PID1 removal unavailable")
		}
	}
}

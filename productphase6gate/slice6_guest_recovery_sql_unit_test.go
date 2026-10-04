//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6GuestOperatorSQLIsFixedReadOnlyAndOutputClosed(t *testing.T) {
	if !strings.HasPrefix(slice6GuestOperatorSelect, "BEGIN READ ONLY;\n") ||
		!strings.Contains(slice6GuestOperatorSelect, "SET LOCAL statement_timeout='3000ms';") ||
		!strings.Contains(slice6GuestOperatorSelect, "FROM sandbox_runtime_product.guest_bindings ") ||
		!strings.Contains(slice6GuestOperatorSelect, "current_database()='product'") ||
		!strings.Contains(slice6GuestOperatorSelect, "current_user='postgres'") ||
		!strings.Contains(slice6GuestOperatorSelect, "(connection_nonce IS NULL)::text") ||
		!strings.Contains(slice6GuestOperatorSelect, "expires_at>clock_timestamp()") ||
		!strings.Contains(slice6GuestOperatorSelect, "tenant_id=:'tenant_id'") ||
		!strings.Contains(slice6GuestOperatorSelect, "workspace_id=:'workspace_id'") ||
		!strings.Contains(slice6GuestOperatorSelect, "slot_key=:'slot_key'") ||
		!strings.Contains(slice6GuestOperatorSelect, "slot_profile_id=:'slot_profile_id'") ||
		!strings.Contains(slice6GuestOperatorSelect, "slot_generation=:'slot_generation'::bigint") ||
		!strings.Contains(slice6GuestOperatorSelect, "guest_id=:'guest_id'") ||
		!strings.Contains(slice6GuestOperatorSelect, "binding_generation=:'binding_generation'::bigint") ||
		!strings.HasPrefix(slice6GuestOperatorBackendSelect, "BEGIN READ ONLY;\n") ||
		!strings.Contains(slice6GuestOperatorBackendSelect, "pg_catalog.pg_stat_activity") ||
		strings.ContainsAny(slice6GuestOperatorSelect, "\\") {
		t.Fatal("fixed operator SQL lost its reviewed read-only scope")
	}
	const good = "disconnected|true|true|1791087000000000\n"
	state, nonceNull, unexpired, expiry, err := slice6CheckGuestOperatorRow([]byte(good), nil, false)
	if err != nil || state != "disconnected" || !nonceNull || !unexpired || expiry != 1791087000000000 {
		t.Fatalf("closed SQL readback = %q/%t/%t/%d err=%v", state, nonceNull, unexpired, expiry, err)
	}
	for _, test := range []struct {
		name     string
		output   []byte
		command  error
		overflow bool
	}{
		{"raw nonce", []byte("disconnected|secret|true|1791087000000000\n"), nil, false},
		{"empty not null", []byte("disconnected||true|1791087000000000\n"), nil, false},
		{"expired", []byte("disconnected|true|false|1791087000000000\n"), nil, false},
		{"bare boolean", []byte("disconnected|t|true|1791087000000000\n"), nil, false},
		{"duplicate", []byte(good + good), nil, false},
		{"missing", nil, nil, false},
		{"extra field", []byte("disconnected|true|true|1791087000000000|x\n"), nil, false},
		{"whitespace", []byte(" disconnected|true|true|1791087000000000\n"), nil, false},
		{"bad expiry", []byte("disconnected|true|true|0\n"), nil, false},
		{"SQL error", []byte(good), errors.New("test SQL error"), false},
		{"overflow", []byte(good), nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, _, err := slice6CheckGuestOperatorRow(test.output, test.command, test.overflow); err == nil {
				t.Fatal("invalid privileged readback output was accepted")
			}
		})
	}
	if bytes.Contains([]byte(slice6GuestOperatorSelect), []byte("connection_nonce||")) {
		t.Fatal("raw nonce leaked into operator output")
	}
}

func TestSlice6GuestOperatorFormalSourceCannotFallBackToComponent(t *testing.T) {
	runID := strings.Repeat("a", 32)
	target := slice6GuestOperatorTarget{Run: slice6DockerRun{id: runID},
		PostgresID: strings.Repeat("b", 64), ImageID: "sha256:" + strings.Repeat("c", 64),
		ImageRef: "postgres:16-alpine@sha256:" + strings.Repeat("d", 64),
		UID:      70, GID: 70, TenantID: "tenant-phase6-" + runID,
		WorkspaceID: "wrk_" + strings.Repeat("e", 32), SlotKey: "primary-code",
		SlotProfileID: "coding-shell-v1", SlotGeneration: 1,
		GuestID: "gst_" + strings.Repeat("f", 32), BindingGeneration: 1}
	if !target.valid() {
		t.Fatal("valid component target unavailable")
	}
	if _, err := slice6ReadGuestOperatorFormalPG(t.Context(), target,
		slice6GuestOperatorFormalSource{}, "sha256:"+strings.Repeat("d", 64), []byte("fixture HBA"),
		slice6GuestOperatorInitialConnected, 0); err == nil {
		t.Fatal("formal readback admitted a component-only target")
	}
	if _, err := slice6ProveGuestOperatorFormalSource(context.Background(), target,
		phase6security.Profile{}, nil, nil, nil); err == nil {
		t.Fatal("formal source proof admitted an empty Profile/topology")
	}
	good := []byte(`[{"Labels":{"` + slice6RunLabel + `":"` + runID + `"}}]`)
	if !slice6GuestOperatorNetworkRunLabel(good, runID) ||
		slice6GuestOperatorNetworkRunLabel(good, strings.Repeat("b", 32)) ||
		slice6GuestOperatorNetworkRunLabel([]byte(`[{"Labels":{}},{"Labels":{}}]`), runID) {
		t.Fatal("formal network run label binding drifted")
	}
	observed := phase6security.NetworkObservation{Endpoints: []phase6security.NetworkEndpointObservation{
		{ContainerID: target.PostgresID, IPv4Address: "10.77.0.3"}}}
	if !slice6GuestOperatorEndpointPresent(observed, target.PostgresID, "10.77.0.3") ||
		slice6GuestOperatorEndpointPresent(observed, target.PostgresID, "10.77.0.4") {
		t.Fatal("formal PostgreSQL endpoint binding drifted")
	}
}

func TestSlice6GuestOperatorAStageNineRawNetworks(t *testing.T) {
	members := make(map[string]slice6GuestPGMember, 9)
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		state := slice6GuestOperatorAStageState(path.Dialer)
		id := ""
		if state == "started" {
			id = strings.Repeat("b", 64)
		} else if state == "migrated_exited_removed" {
			id = strings.Repeat("c", 64)
		}
		member := slice6GuestPGMember{State: state, ID: id}
		if state == "migrated_exited_removed" {
			member.Migration = &slice6ProductMigrationExitProof{}
		}
		members[path.Dialer] = member
	}
	if err := slice6ValidateGuestOperatorAStageMembers(members); err != nil {
		t.Fatalf("%v: %+v", err, members)
	}
	pgID := strings.Repeat("a", 64)
	checked := 0
	for _, network := range phase6security.Slice6DesiredFinalServiceBridges() {
		if len(network.ExternalServices) != 1 || network.ExternalServices[0] != "postgres" {
			continue
		}
		member := members[network.Principals[0]]
		pgIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(network.Name, "postgres")
		if err != nil {
			t.Fatal(err)
		}
		containers := map[string]map[string]string{pgID: {"IPv4Address": pgIP + "/24"}}
		if member.State == "started" {
			peerIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(network.Name, network.Principals[0])
			if err != nil {
				t.Fatal(err)
			}
			containers[member.ID] = map[string]string{"IPv4Address": peerIP + "/24"}
		}
		makeRaw := func() []byte {
			t.Helper()
			raw, err := json.Marshal([]any{map[string]any{
				"Name": network.Name, "Id": fmt.Sprintf("%064x", checked+1), "Driver": "bridge",
				"Scope": "local", "Internal": true, "Attachable": false, "Ingress": false,
				"EnableIPv4": true, "EnableIPv6": false,
				"Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
					"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"},
				"IPAM":       map[string]any{"Config": []map[string]string{{"Subnet": network.IPv4Subnet, "Gateway": ""}}},
				"Containers": containers,
			}})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		if _, err := slice6ObserveGuestOperatorPGStageNetwork(makeRaw(), network, member, pgID); err != nil {
			t.Fatalf("source-derived A-prime raw bridge %s rejected: %v", network.Name, err)
		}
		containers[strings.Repeat("d", 64)] = map[string]string{"IPv4Address": pgIP + "/24"}
		if _, err := slice6ObserveGuestOperatorPGStageNetwork(makeRaw(), network, member, pgID); err == nil {
			t.Fatalf("unknown endpoint admitted on %s", network.Name)
		}
		delete(containers, strings.Repeat("d", 64))
		if member.State != "started" {
			wrongMember := member
			wrongMember.ID = strings.Repeat("e", 64)
			if member.State == "not_started" {
				if _, err := slice6ObserveGuestOperatorPGStageNetwork(makeRaw(), network, wrongMember, pgID); err == nil {
					t.Fatalf("not-started member retained a container ID on %s", network.Name)
				}
			}
			containers[strings.Repeat("e", 64)] = map[string]string{"IPv4Address": pgIP + "/24"}
			if _, err := slice6ObserveGuestOperatorPGStageNetwork(makeRaw(), network, member, pgID); err == nil {
				t.Fatalf("exited/not-started dialer admitted on %s", network.Name)
			}
			delete(containers, strings.Repeat("e", 64))
		}
		checked++
	}
	if checked != 9 {
		t.Fatalf("observed %d PG bridges, want nine", checked)
	}
	drift := make(map[string]slice6GuestPGMember, len(members))
	for key, value := range members {
		drift[key] = value
	}
	drift["product-migration-job"] = slice6GuestPGMember{State: "started", ID: strings.Repeat("c", 64)}
	if slice6ValidateGuestOperatorAStageMembers(drift) == nil {
		t.Fatal("completed migration silently restarted")
	}
}

func TestSlice6GuestOperatorTargetHasNoFreeSQLIdentifiers(t *testing.T) {
	runID := strings.Repeat("a", 32)
	target := slice6GuestOperatorTarget{Run: slice6DockerRun{id: runID},
		PostgresID: strings.Repeat("b", 64), ImageID: "sha256:" + strings.Repeat("c", 64),
		ImageRef: "postgres:16-alpine@sha256:" + strings.Repeat("d", 64),
		UID:      70, GID: 70, TenantID: "tenant-phase6-" + runID,
		WorkspaceID: "wrk_" + strings.Repeat("e", 32), SlotKey: "primary-code",
		SlotProfileID:  "coding-shell-v1",
		SlotGeneration: 1, GuestID: "gst_" + strings.Repeat("f", 32), BindingGeneration: 1}
	if !target.valid() {
		t.Fatal("fixed operator tuple rejected")
	}
	for _, mutate := range []func(*slice6GuestOperatorTarget){
		func(v *slice6GuestOperatorTarget) { v.TenantID = "tenant-phase6-" + strings.Repeat("b", 32) },
		func(v *slice6GuestOperatorTarget) { v.WorkspaceID = "wrk';DROP_TABLE" },
		func(v *slice6GuestOperatorTarget) { v.SlotKey = "desktop" },
		func(v *slice6GuestOperatorTarget) { v.SlotProfileID = "different-profile" },
		func(v *slice6GuestOperatorTarget) { v.GuestID = "gst_\nother" },
		func(v *slice6GuestOperatorTarget) { v.BindingGeneration = 0 },
		func(v *slice6GuestOperatorTarget) { v.UID = 0 },
		func(v *slice6GuestOperatorTarget) { v.ImageRef = "postgres:latest" },
	} {
		changed := target
		mutate(&changed)
		if changed.valid() {
			t.Fatal("unscoped operator SQL target was accepted")
		}
	}
}

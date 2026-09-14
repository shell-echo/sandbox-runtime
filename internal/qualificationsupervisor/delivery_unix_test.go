//go:build darwin || linux

package qualificationsupervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func deliveryInvocationValue(a *PhaseAdmission, maxBytes int64) map[string]any {
	locations := a.Locations()
	phase := a.phase
	descriptor := map[string]any{
		"channel_id": "controller-a-provider", "role": "provider_credentials", "actor": "controller_a",
		"media_type": "application/vnd.example.credentials+json", "max_bytes": maxBytes, "file_descriptor": 3,
	}
	return map[string]any{
		"format_version": 1, "protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion,
		"message_type": "invocation", "invocation_id": "invocation-" + phase, "phase": phase,
		"profile_path": locations.ProfilePath, "provider_origin": locations.ProviderOrigin,
		"gateway_probe_endpoint": locations.GatewayProbeEndpoint, "caller_state_root": locations.CallerStateRoot,
		"credential_channel_descriptors": []any{descriptor},
	}
}

func marshalDeliveryInvocation(t *testing.T, value map[string]any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func observedDeliveryProbe(t *testing.T, mode string) *StartedProcess {
	t.Helper()
	_, process, codec := startedStartupProbe(t, mode)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := process.ObserveStartup(ctx, codec); err != nil {
		t.Fatal(err)
	}
	return process
}

func TestDeliverInvocationWritesExactEOFFramedInputs(t *testing.T) {
	process := observedDeliveryProbe(t, "delivery")
	document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
	secret := []byte("provider-secret")
	stats, err := process.DeliverInvocation(context.Background(), document, []CredentialPayload{{
		ChannelID: "controller-a-provider", Data: secret,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.InvocationBytes != int64(len(document)) || stats.CredentialChannelCount != 1 ||
		stats.CredentialPayloadBytes != int64(len(secret)) || string(secret) != "provider-secret" ||
		process.core.admission.Machine().State() != protocol.PhaseStateAwaitingInvocationAcceptance {
		t.Fatalf("wrong delivery result: %+v", stats)
	}
	select {
	case <-process.core.stderrDone:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not finish delivery observation")
	}
	want := fmt.Sprintf("delivery-ok:%d:%d\n", len(document), len(secret))
	wantBytes := len("no-input-before-startup\n") + len(want)
	if count, err, done := process.core.stderrResult(); !done || err != nil || count != int64(wantBytes) {
		t.Fatal("child did not observe exact delivery", count, err, done)
	}
	for _, index := range []int{0, 3, 4, 5, 6, 7, 8, 9, 10} {
		if _, err := process.core.parent[index].Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("input endpoint retained", index, err)
		}
	}
	stored, ok := process.DeliveryStats()
	if !ok || stored != stats {
		t.Fatal("delivery stats not retained")
	}
	copy := *process
	if _, err := copy.DeliverInvocation(context.Background(), document, []CredentialPayload{{
		ChannelID: "controller-a-provider", Data: secret,
	}}); err == nil || !errors.Is(err, ErrDelivery) {
		t.Fatal("duplicate delivery accepted", err)
	}
	select {
	case <-process.core.done:
	case <-time.After(7 * time.Second):
		t.Fatal("duplicate delivery did not reclaim process")
	}
}

func TestDeliverInvocationRejectsWrongOrderAndCanceledInput(t *testing.T) {
	path := buildStartupProbe(t, "valid")
	for _, kind := range []string{"before-startup", "nil-context-after-startup", "canceled-after-startup", "process-context-canceled"} {
		t.Run(kind, func(t *testing.T) {
			codec, err := protocol.NewCodec(context.Background(), "../..")
			if err != nil {
				t.Fatal(err)
			}
			runContext := context.Background()
			var runCancel context.CancelFunc
			if kind == "process-context-canceled" {
				runContext, runCancel = context.WithCancel(runContext)
				defer runCancel()
			}
			_, launch := preparedProbeContext(t, path, runContext)
			processContext, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			process, err := StartProcess(processContext, launch)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = process.Close() })
			if kind != "before-startup" {
				startupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err = process.ObserveStartup(startupContext, codec)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
			}
			document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
			var deliveryContext context.Context = context.Background()
			if kind == "nil-context-after-startup" {
				deliveryContext = nil
			}
			if kind == "canceled-after-startup" {
				var cancel context.CancelFunc
				deliveryContext, cancel = context.WithCancel(deliveryContext)
				cancel()
			}
			if kind == "process-context-canceled" {
				runCancel()
			}
			if _, err := process.DeliverInvocation(deliveryContext, document, []CredentialPayload{{
				ChannelID: "controller-a-provider", Data: []byte("must-not-leak"),
			}}); err == nil || !errors.Is(err, ErrDelivery) || strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("invalid delivery accepted or leaked input", err)
			}
			select {
			case <-process.core.done:
			case <-time.After(7 * time.Second):
				t.Fatal("invalid delivery did not reclaim process")
			}
			if _, ok := process.DeliveryStats(); ok {
				t.Fatal("failed delivery retained stats")
			}
		})
	}
	var zero StartedProcess
	if _, ok := zero.DeliveryStats(); ok {
		t.Fatal("zero process has delivery stats")
	}
	if _, err := zero.DeliverInvocation(context.Background(), nil, nil); err != ErrDelivery {
		t.Fatal(err)
	}
}

func TestDeliverInvocationWriteFailureAndCancellationReap(t *testing.T) {
	t.Run("closed-readers", func(t *testing.T) {
		process := observedDeliveryProbe(t, "close-delivery-input")
		document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
		_, err := process.DeliverInvocation(context.Background(), document, []CredentialPayload{{
			ChannelID: "controller-a-provider", Data: []byte("must-not-leak"),
		}})
		if err == nil || !errors.Is(err, ErrDelivery) || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatal("write failure accepted or leaked input", err)
		}
		select {
		case <-process.core.done:
		case <-time.After(7 * time.Second):
			t.Fatal("write failure did not reap")
		}
	})

	t.Run("blocked-writer-canceled", func(t *testing.T) {
		process := observedDeliveryProbe(t, "block-delivery")
		document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, protocol.MaxCredentialChannelBytes))
		secret := bytes.Repeat([]byte{'s'}, int(protocol.MaxCredentialChannelBytes))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := process.DeliverInvocation(ctx, document, []CredentialPayload{{
			ChannelID: "controller-a-provider", Data: secret,
		}})
		if err == nil || !errors.Is(err, ErrDelivery) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked delivery did not honor cancellation", err)
		}
		if secret[0] != 's' || secret[len(secret)-1] != 's' {
			t.Fatal("caller-owned payload mutated")
		}
		select {
		case <-process.core.done:
		case <-time.After(7 * time.Second):
			t.Fatal("canceled write did not reap")
		}
	})
}

func TestPrepareDeliveryValidatesBindingsAndBoundsBeforeWrite(t *testing.T) {
	codec, err := protocol.NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	frozen, admission := launchFixture(t)
	defer frozen.Close()
	actor := "controller_a"
	core := &processCore{admission: admission, codec: codec, startup: protocol.StartupIdentity{
		CredentialChannels: []protocol.CredentialChannelRequirement{{
			ChannelID: "controller-a-provider", Role: "provider_credentials", Actor: &actor,
			MediaType: "application/vnd.example.credentials+json", MaxBytes: 4096,
		}},
	}}
	validValue := deliveryInvocationValue(admission, 4096)
	validCredential := []CredentialPayload{{ChannelID: "controller-a-provider", Data: []byte("provider-secret")}}
	plan, err := prepareDelivery(core, marshalDeliveryInvocation(t, validValue), validCredential)
	if err != nil || plan.stats.CredentialPayloadBytes != int64(len("provider-secret")) {
		t.Fatal("valid delivery rejected", err)
	}
	validCredential[0].Data[0] = 'X'
	if string(plan.credentials[0].data) != "provider-secret" {
		t.Fatal("private delivery buffer aliases caller input")
	}
	wipeCredentials(plan.credentials)
	if plan.credentials[0].data[0] != 0 {
		t.Fatal("private credential buffer not wiped")
	}

	tests := []struct {
		name        string
		mutate      func(map[string]any)
		credentials []CredentialPayload
	}{
		{name: "wrong-phase", mutate: func(v map[string]any) { v["phase"] = "reconstruction" }, credentials: validCredential},
		{name: "profile-path", mutate: func(v map[string]any) { v["profile_path"] = "/other/profile.json" }, credentials: validCredential},
		{name: "provider-origin", mutate: func(v map[string]any) { v["provider_origin"] = "https://other.invalid" }, credentials: validCredential},
		{name: "gateway-endpoint", mutate: func(v map[string]any) { v["gateway_probe_endpoint"] = "wss://other.invalid/terminal" }, credentials: validCredential},
		{name: "state-root", mutate: func(v map[string]any) { v["caller_state_root"] = "/other-state" }, credentials: validCredential},
		{name: "role", mutate: func(v map[string]any) {
			v["credential_channel_descriptors"].([]any)[0].(map[string]any)["role"] = "provider_trust"
		}, credentials: validCredential},
		{name: "actor", mutate: func(v map[string]any) { v["credential_channel_descriptors"].([]any)[0].(map[string]any)["actor"] = nil }, credentials: validCredential},
		{name: "media-type", mutate: func(v map[string]any) {
			v["credential_channel_descriptors"].([]any)[0].(map[string]any)["media_type"] = "application/other"
		}, credentials: validCredential},
		{name: "max-bytes", mutate: func(v map[string]any) {
			v["credential_channel_descriptors"].([]any)[0].(map[string]any)["max_bytes"] = 4095
		}, credentials: validCredential},
		{name: "transport-fd", mutate: func(v map[string]any) {
			v["credential_channel_descriptors"].([]any)[0].(map[string]any)["file_descriptor"] = 11
		}, credentials: validCredential},
		{name: "missing-payload", credentials: nil},
		{name: "wrong-payload-id", credentials: []CredentialPayload{{ChannelID: "other", Data: []byte("x")}}},
		{name: "duplicate-payload-id", credentials: []CredentialPayload{{ChannelID: "controller-a-provider"}, {ChannelID: "controller-a-provider"}}},
		{name: "payload-over-channel-limit", credentials: []CredentialPayload{{ChannelID: "controller-a-provider", Data: make([]byte, 4097)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := deliveryInvocationValue(admission, 4096)
			if test.mutate != nil {
				test.mutate(value)
			}
			if plan, err := prepareDelivery(core, marshalDeliveryInvocation(t, value), test.credentials); plan != nil || err == nil {
				t.Fatal("invalid delivery prepared", err)
			}
		})
	}
	if plan, err := prepareDelivery(core, make([]byte, protocol.MaxInvocationBytes+1), validCredential); plan != nil || err == nil {
		t.Fatal("oversized invocation prepared", err)
	}
	if plan, err := prepareDelivery(core, []byte(`{"invalid":true}`), validCredential); plan != nil || err == nil {
		t.Fatal("invalid invocation prepared", err)
	}
	if _, err := writeAllAndClose(nil, nil); err != ErrDelivery {
		t.Fatal(err)
	}
}

func TestPrepareDeliveryRejectsCredentialTotalLimit(t *testing.T) {
	codec, err := protocol.NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	frozen, admission := launchFixture(t)
	defer frozen.Close()
	value := deliveryInvocationValue(admission, protocol.MaxCredentialChannelBytes)
	value["credential_channel_descriptors"] = []any{}
	actor := "controller_a"
	core := &processCore{admission: admission, codec: codec}
	credentials := make([]CredentialPayload, 0, 5)
	for index := 0; index < 5; index++ {
		id := fmt.Sprintf("channel-%d", index)
		descriptor := map[string]any{
			"channel_id": id, "role": "provider_credentials", "actor": "controller_a",
			"media_type": "application/example", "max_bytes": protocol.MaxCredentialChannelBytes, "file_descriptor": 3 + index,
		}
		value["credential_channel_descriptors"] = append(value["credential_channel_descriptors"].([]any), descriptor)
		core.startup.CredentialChannels = append(core.startup.CredentialChannels, protocol.CredentialChannelRequirement{
			ChannelID: id, Role: "provider_credentials", Actor: &actor, MediaType: "application/example", MaxBytes: protocol.MaxCredentialChannelBytes,
		})
		size := int(protocol.MaxCredentialChannelBytes)
		if index == 4 {
			size = 1
		}
		credentials = append(credentials, CredentialPayload{ChannelID: id, Data: make([]byte, size)})
	}
	if plan, err := prepareDelivery(core, marshalDeliveryInvocation(t, value), credentials); plan != nil || err == nil {
		t.Fatal("credential total overflow prepared", err)
	}
}

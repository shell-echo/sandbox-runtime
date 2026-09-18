//go:build darwin || linux

// Local startup-frame probe, not an external caller implementation.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var mode = "valid"

func main() {
	if mode == "empty-exit" {
		return
	}
	if mode == "delay" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if !noInput() {
		fmt.Fprintln(os.Stderr, "input-observed")
		os.Exit(3)
	}
	if mode == "close-delivery-input" {
		closeDeliveryInputs()
	}
	if mode == "malformed" {
		fmt.Fprintln(os.Stdout, `{"secret":"must-not-leak"`)
		for {
			time.Sleep(time.Hour)
		}
	}
	identity := startupIdentity()
	if mode == "wrong-authority" {
		identity["protocol_semantics_digest"] = "sha256:" + strings.Repeat("f", 64)
	}
	if mode == "duplicate-channel" {
		channels := identity["credential_channel_requirements"].([]any)
		identity["credential_channel_requirements"] = append(channels, map[string]any{
			"channel_id": "controller-a-provider", "role": "provider_trust", "actor": nil,
			"media_type": "application/vnd.example.trust+json", "max_bytes": 2048,
		})
	}
	if mode == "non-startup" {
		identity = map[string]any{"format_version": 1, "protocol_id": "sandbox-runtime-external-caller-adapter-v1", "protocol_version": "1.0.0", "message_type": "protocol_error", "sequence": 0, "invocation_id": nil, "phase": nil, "error_code": "invalid_invocation", "terminal": true}
	}
	if mode == "truncated-exit" {
		document, _ := json.Marshal(identity)
		_, _ = os.Stdout.Write(document)
		return
	}
	if json.NewEncoder(os.Stdout).Encode(identity) != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "no-input-before-startup")
	if mode == "close-delivery-input" {
		fmt.Fprintln(os.Stderr, "delivery-inputs-closed")
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "block-delivery" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "delivery" {
		observeDelivery()
		return
	}
	if mode == "completion" || mode == "nonclean-completion" || mode == "extra-after-terminal" ||
		mode == "case-stall" || mode == "stderr-overflow" {
		message := observeDelivery()
		emitCompletion(message)
		if mode == "nonclean-completion" {
			os.Exit(9)
		}
		return
	}
	if mode == "valid-exit" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

type invocation struct {
	MessageType  string `json:"message_type"`
	InvocationID string `json:"invocation_id"`
	Phase        string `json:"phase"`
	Descriptors  []struct {
		ChannelID      string `json:"channel_id"`
		FileDescriptor int    `json:"file_descriptor"`
	} `json:"credential_channel_descriptors"`
}

func observeDelivery() invocation {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, 32769))
	if err != nil || len(document) == 0 || len(document) > 32768 {
		os.Exit(4)
	}
	var message invocation
	if json.Unmarshal(document, &message) != nil || message.MessageType != "invocation" || len(message.Descriptors) != 1 ||
		message.Descriptors[0].ChannelID != "controller-a-provider" || message.Descriptors[0].FileDescriptor != 3 {
		os.Exit(4)
	}
	credentialTotal := 0
	for descriptor := 3; descriptor <= 10; descriptor++ {
		file := os.NewFile(uintptr(descriptor), fmt.Sprintf("credential-%d", descriptor))
		payload, err := io.ReadAll(io.LimitReader(file, 1048577))
		if err != nil || len(payload) > 1048576 {
			os.Exit(4)
		}
		if descriptor == 3 {
			if string(payload) != "provider-secret" {
				os.Exit(4)
			}
			credentialTotal += len(payload)
		} else if len(payload) != 0 {
			os.Exit(4)
		}
	}
	fmt.Fprintf(os.Stderr, "delivery-ok:%d:%d\n", len(document), credentialTotal)
	return message
}

func emitCompletion(message invocation) {
	encoder := json.NewEncoder(os.Stdout)
	sequence := 1
	emit := func(value map[string]any) {
		value["format_version"] = 1
		value["protocol_id"] = "sandbox-runtime-external-caller-adapter-v1"
		value["protocol_version"] = "1.0.0"
		value["sequence"] = sequence
		value["invocation_id"] = message.InvocationID
		value["phase"] = message.Phase
		sequence++
		if encoder.Encode(value) != nil {
			os.Exit(5)
		}
	}
	emit(map[string]any{"message_type": "invocation_accepted"})
	if mode == "stderr-overflow" {
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 262145))
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "case-stall" {
		emit(map[string]any{"message_type": "scenario_started", "case_id": initialCases[0]})
		for {
			time.Sleep(time.Hour)
		}
	}
	cases := initialCases
	if message.Phase == "reconstruction" {
		cases = reconstructionCases
	}
	for _, caseID := range cases {
		emit(map[string]any{
			"message_type": "scenario_result", "case_id": caseID, "disposition": "not_executed",
			"interactions": []any{}, "assertions": []any{}, "observation_ids": []any{}, "reason_code": "prerequisite_not_satisfied",
		})
	}
	emit(map[string]any{"message_type": "invocation_finished", "completion": "stopped"})
	if mode == "extra-after-terminal" {
		_, _ = os.Stdout.Write([]byte{'x'})
	}
}

var initialCases = []string{
	"initial.locked-capability-discovery",
	"initial.protected-lifecycle-create",
	"initial.replay-semantics",
	"initial.lifecycle-completion-and-status",
	"initial.exec-result-and-usage-evidence",
	"initial.stale-fencing-rejection",
	"initial.exec-cancellation",
	"initial.terminal-session-and-opaque-handoff",
	"initial.gateway-terminal-byte-round-trip",
	"initial.gateway-wrong-caller-and-cross-tenant-rejection",
	"initial.gateway-grant-expiry",
	"initial.gateway-revocation",
	"initial.artifact-staging-and-evidence",
	"initial.provider-cross-tenant-artifact-rejection",
	"initial.provider-mtls-caller-binding-rejection",
}

var reconstructionCases = []string{
	"reconstruction.locked-capability-discovery",
	"reconstruction.durable-lifecycle",
	"reconstruction.retained-exec-usage-and-artifact-evidence",
	"reconstruction.durable-opaque-handoff",
	"reconstruction.same-shell-reconnect",
}

func closeDeliveryInputs() {
	_ = os.Stdin.Close()
	for descriptor := 3; descriptor <= 10; descriptor++ {
		_ = unix.Close(descriptor)
	}
}

func noInput() bool {
	for _, fd := range []int{0, 3, 4, 5, 6, 7, 8, 9, 10} {
		if unix.SetNonblock(fd, true) != nil {
			return false
		}
		var b [1]byte
		n, err := unix.Read(fd, b[:])
		if unix.SetNonblock(fd, false) != nil || n > 0 || !errors.Is(err, unix.EAGAIN) {
			return false
		}
	}
	return true
}

func startupIdentity() map[string]any {
	release := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	maxBytes := 4096
	if mode == "block-delivery" {
		maxBytes = 1048576
	}
	channel := map[string]any{"channel_id": "controller-a-provider", "role": "provider_credentials", "actor": "controller_a", "media_type": "application/vnd.example.credentials+json", "max_bytes": maxBytes}
	return map[string]any{
		"format_version": 1, "protocol_id": "sandbox-runtime-external-caller-adapter-v1", "protocol_version": "1.0.0", "message_type": "startup_identity", "sequence": 0,
		"protocol_schema_digest":    "sha256:7948265be2f90f8c695c62340ab57f451b0771c104e9505d01d778063fca23a6",
		"protocol_semantics_digest": "sha256:5e0521ff6df2451384c717fd62c0335d3e726164f7488ac191430b263affe82c",
		"caller_release_identity":   release, "adapter_release_identity": release,
		"contract_revision": "98995384c60a924f25ca58d3b7e561207bfa5be8", "contract_tree": "0a627baed11c8a6ddbe8a24bbc1869e4f85edc16",
		"profile_id": "sandbox-runtime-external-caller-coding-shell-v1", "profile_version": "1.0.0", "profile_digest": "sha256:ed57cfcb72c60d3efe6aca872e50c38033200e0f1cb8d2ae076bf6593a0afce6",
		"expected_values_injected_by_harness": false, "credential_channel_requirements": []any{channel},
	}
}

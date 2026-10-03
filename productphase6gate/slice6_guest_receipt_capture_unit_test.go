//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

func TestSlice6GuestReceiptPairRejectsCausalDrift(t *testing.T) {
	first := "sha256:" + strings.Repeat("a", 64)
	second := "sha256:" + strings.Repeat("b", 64)
	item := func(event, digest, reason string) phase6guestreceipt.Record {
		return phase6guestreceipt.Record{Event: event, AttemptDigest: digest,
			BindingGeneration: 1, Reason: reason}
	}
	base := slice6GuestReceiptPair{
		Product: []phase6guestreceipt.Record{{Event: "begin"},
			item("product_auth_accepted", first, ""),
			item("product_welcome_written", first, ""),
			item("product_peer_installed", first, ""),
			item("product_authority_stale", first, ""),
			item("product_close_completed", first, "authority_stale"),
			item("product_validated_revoked", second, ""),
			{Event: "seal"}},
		Guest: []phase6guestreceipt.Record{{Event: "begin"},
			item("guest_hello_written", first, ""),
			item("guest_welcome_accepted", first, ""),
			item("guest_read_terminated", first, ""),
			item("guest_hello_written", second, ""),
			{Event: "seal"}},
	}
	for i := range base.Product {
		base.Product[i].Sequence = uint64(i + 1)
	}
	for i := range base.Guest {
		base.Guest[i].Sequence = uint64(i + 1)
	}
	if err := base.verifyRevoke(1); err != nil {
		t.Fatal("matched accepted, closed, and revoked signed attempts were rejected")
	}
	for _, change := range []struct {
		name  string
		apply func(*slice6GuestReceiptPair)
	}{
		{"missing completed close", func(p *slice6GuestReceiptPair) { p.Product[5].Event = "product_authority_stale" }},
		{"generic close", func(p *slice6GuestReceiptPair) { p.Product[5].Reason = "handler_shutdown" }},
		{"revoked attempt digest mismatch", func(p *slice6GuestReceiptPair) { p.Guest[4].AttemptDigest = first }},
		{"generation drift", func(p *slice6GuestReceiptPair) { p.Guest[4].BindingGeneration = 2 }},
		{"missing revoked state", func(p *slice6GuestReceiptPair) { p.Product[6].Event = "product_auth_accepted" }},
		{"close before stale", func(p *slice6GuestReceiptPair) { p.Product[5].Sequence = 4 }},
		{"revoked before completed close", func(p *slice6GuestReceiptPair) { p.Product[6].Sequence = 5 }},
		{"retry before read termination", func(p *slice6GuestReceiptPair) { p.Guest[4].Sequence = 4 }},
		{"extra unjoined attempt", func(p *slice6GuestReceiptPair) {
			p.Guest = append(p.Guest[:len(p.Guest)-1],
				phase6guestreceipt.Record{Event: "guest_hello_written", AttemptDigest: "sha256:" + strings.Repeat("c", 64), BindingGeneration: 1},
				p.Guest[len(p.Guest)-1])
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			mutated := slice6GuestReceiptPair{Product: append([]phase6guestreceipt.Record(nil), base.Product...),
				Guest: append([]phase6guestreceipt.Record(nil), base.Guest...)}
			change.apply(&mutated)
			if mutated.verifyRevoke(1) == nil {
				t.Fatal("causal drift was accepted")
			}
		})
	}
}

func TestSlice6GuestReceiptAttachedDockerNoIssuer(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_RECEIPT_CAPTURE_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_RECEIPT_CAPTURE_DOCKER=1 for attached Docker collector drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("attached receipt collector exact cleanup: %v", err)
		}
	})
	profile := "sha256:" + strings.Repeat("a", 64)
	config := "sha256:" + strings.Repeat("b", 64)
	begin := phase6guestreceipt.Record{Protocol: phase6guestreceipt.Protocol, Role: "guest",
		Event: "begin", Sequence: 1, ElapsedNanos: 1, UnixMillis: 1_700_000_000_000,
		ProfileDigest: profile, ConfigDigest: config}
	seal := phase6guestreceipt.Record{Protocol: phase6guestreceipt.Protocol, Role: "guest",
		Event: "seal", Sequence: 2, ElapsedNanos: 2, UnixMillis: 1_700_000_000_001}
	beginJSON, err := json.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	sealJSON, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-receipt-collector-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
		"--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		"-e", "BEGIN="+string(beginJSON), "-e", "SEAL="+string(sealJSON),
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
		"printf '%s\\n%s\\n' \"$BEGIN\" \"$SEAL\"")
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create no-issuer attached Docker probe failed")
	}
	capture, err := slice6StartGuestReceiptCapture(t, ctx, id, "guest", profile, config)
	if err != nil {
		t.Fatal("start no-issuer attached Docker collector failed")
	}
	defer capture.abort()
	records, err := capture.verifyStopped(ctx, run, id, 0)
	if err != nil || len(records) != 2 {
		t.Fatal("attached PID1 stdout did not produce exact closed private receipt")
	}
	info, err := os.Stat(capture.path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("private receipt capture mode drift")
	}
	parent, err := os.Stat(filepath.Dir(capture.path))
	if err != nil || parent.Mode().Perm() != 0o700 {
		t.Fatal("private receipt capture directory mode drift")
	}
	created, err = run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-receipt-exit-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
		"--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		"-e", "BEGIN="+string(beginJSON), "-e", "SEAL="+string(sealJSON),
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
		"printf '%s\\n%s\\n' \"$BEGIN\" \"$SEAL\"; exit 3")
	id = strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create nonzero-exit attached Docker probe failed")
	}
	capture, err = slice6StartGuestReceiptCapture(t, ctx, id, "guest", profile, config)
	if err != nil {
		t.Fatal("start nonzero-exit attached Docker collector failed")
	}
	defer capture.abort()
	if _, err := capture.verifyStopped(ctx, run, id, 2); err == nil {
		t.Fatal("collector accepted a mismatched nonzero exit code")
	}
	records, err = capture.verifyStopped(ctx, run, id, 3)
	if err != nil || len(records) != 2 {
		t.Fatal("collector rejected the exact observed nonzero exit code")
	}
}

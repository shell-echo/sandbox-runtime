//go:build darwin || linux

package qualificationsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

func commitmentFixture(t *testing.T) (*PreparedConfiguration, *LocationFiles, *Executable) {
	t.Helper()
	p := filesystemFixture(t)
	f, err := OpenLocationFiles(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, path, digest := executableFixture(t)
	e, err := OpenExecutable(context.Background(), p, path, digest, 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return p, f, e
}

func freezeFixture(t *testing.T) *FrozenPreflight {
	t.Helper()
	p, f, e := commitmentFixture(t)
	c, err := FinalizePreflight(context.Background(), p, f, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCommitmentDigestAndExclusiveTransfer(t *testing.T) {
	p, f, e := commitmentFixture(t)
	fCopy, eCopy := *f, *e
	// Independently enumerated full preimage; no production DTO reuse.
	expected := map[string]any{
		"format_version": 1, "locations": p.Locations(), "executable_path": e.path,
		"executable_digest": e.digest, "executable_byte_limit": int64(1024),
		"profile_digest": qualificationprofile.ExpectedProfileDigest, "profile_file_digest": f.profileDigest,
		"protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion,
		"protocol_schema_digest": protocol.ExpectedProtocolSchemaDigest, "protocol_semantics_digest": protocol.ExpectedProtocolSemanticsDigest,
		"transport_id": "darwin-linux-inherited-pipe-v1",
	}
	doc, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(doc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	c, err := FinalizePreflight(context.Background(), p, f, e)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Digest() != "sha256:"+hex.EncodeToString(sum[:]) || c.Digest() == p.Digest() {
		t.Fatal("wrong full commitment")
	}
	if f.profile != nil || e.file != nil {
		t.Fatal("sources retained ownership")
	}
	if _, err := FinalizePreflight(context.Background(), p, &fCopy, &eCopy); err != ErrPreflight {
		t.Fatal("copied sources minted another commitment", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := c.AdmitPhase(context.Background(), "initial")
	if err != nil {
		t.Fatal(err)
	}
	if a.Locations() != p.Locations() || a.Recheck(context.Background()) != nil {
		t.Fatal("lost binding")
	}
	copyToken := *a
	if copyToken.Recheck(context.Background()) != ErrPreflight {
		t.Fatal("copied admission accepted")
	}
	copyFrozen := *c
	if err := copyFrozen.Close(); err != nil {
		t.Fatal(err)
	}
	if a.Recheck(context.Background()) != ErrPreflight || c.Close() != nil {
		t.Fatal("close did not revoke shared custody")
	}
	if _, err := os.Stat(p.locations.CallerStateRoot); err != nil {
		t.Fatal("close removed state", err)
	}
}

func TestCommitmentFailuresLeaveSourceOwnership(t *testing.T) {
	for _, kind := range []string{"mismatch", "closed-files", "closed-executable", "nil-context", "canceled", "profile-mutation"} {
		t.Run(kind, func(t *testing.T) {
			p, f, e := commitmentFixture(t)
			ctx := context.Background()
			switch kind {
			case "mismatch":
				input := p.Locations()
				input.ProviderOrigin = "https://other.example"
				var err error
				p, err = PrepareConfiguration(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
			case "closed-files":
				_ = f.Close()
			case "closed-executable":
				_ = e.Close()
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "profile-mutation":
				if err := os.Chmod(p.locations.ProfilePath, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := FinalizePreflight(ctx, p, f, e)
			if got != nil || err == nil {
				t.Fatal("invalid finalization accepted")
			}
			if kind == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != ErrPreflight {
				t.Fatal("unsanitized failure", err)
			}
			if f.claim.claimed || e.claim.claimed {
				t.Fatal("failure consumed ownership")
			}
		})
	}
}

func TestCommitmentAdmissionFailureIsAbsorbing(t *testing.T) {
	for _, kind := range []string{"early-reconstruction", "duplicate-initial", "unknown", "changed-executable", "changed-state", "canceled", "nil-context", "closed"} {
		t.Run(kind, func(t *testing.T) {
			c := freezeFixture(t)
			ctx := context.Background()
			phase := "initial"
			switch kind {
			case "early-reconstruction":
				phase = "reconstruction"
			case "duplicate-initial":
				if _, err := c.AdmitPhase(ctx, phase); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				phase = "other"
			case "changed-executable":
				if err := os.Chmod(c.core.executable.path, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-state":
				if err := os.Chmod(c.core.files.configuration.CallerStateRoot, 0755); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "closed":
				_ = c.Close()
			}
			if _, err := c.AdmitPhase(ctx, phase); err == nil {
				t.Fatal("invalid admission accepted")
			}
			if _, err := c.AdmitPhase(context.Background(), "initial"); err == nil {
				t.Fatal("failed commitment revived")
			}
		})
	}
}

// Synthetic protocol events only; this helper never starts a process.
func completeSyntheticInitial(t *testing.T, a *PhaseAdmission) {
	t.Helper()
	codec, err := protocol.NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	release := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	channel := map[string]any{"channel_id": "controller-a-provider", "role": "provider_credentials", "actor": "controller_a", "media_type": "application/vnd.example.credentials+json", "max_bytes": 4096}
	startup := map[string]any{
		"format_version": 1, "protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion, "message_type": "startup_identity", "sequence": 0,
		"protocol_schema_digest": protocol.ExpectedProtocolSchemaDigest, "protocol_semantics_digest": protocol.ExpectedProtocolSemanticsDigest,
		"caller_release_identity": release, "adapter_release_identity": release,
		"contract_revision": "22ba6987ea5fbc37d53942720133c0acad199edd", "contract_tree": "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38",
		"profile_id": qualificationprofile.ProfileID, "profile_version": qualificationprofile.ProfileVersion, "profile_digest": qualificationprofile.ExpectedProfileDigest,
		"expected_values_injected_by_harness": false, "credential_channel_requirements": []any{channel},
	}
	terminal := map[string]any{"format_version": 1, "protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion, "message_type": "protocol_error", "sequence": 1, "invocation_id": nil, "phase": nil, "error_code": "invalid_invocation", "terminal": true}
	var stream bytes.Buffer
	encoder := json.NewEncoder(&stream)
	if err := encoder.Encode(startup); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Encode(terminal); err != nil {
		t.Fatal(err)
	}
	decoder := codec.NewOutputDecoder(&stream)
	machine := a.Machine()
	if _, err := machine.ReadStartup(decoder); err != nil {
		t.Fatal(err)
	}
	if err := machine.AuthorizeInvocationInput(); err != nil {
		t.Fatal(err)
	}
	channel["file_descriptor"] = 3
	loc := a.Locations()
	inv := map[string]any{"format_version": 1, "protocol_id": protocol.ProtocolID, "protocol_version": protocol.ProtocolVersion, "message_type": "invocation", "invocation_id": "invocation-initial", "phase": "initial", "profile_path": loc.ProfilePath, "provider_origin": loc.ProviderOrigin, "gateway_probe_endpoint": loc.GatewayProbeEndpoint, "caller_state_root": loc.CallerStateRoot, "credential_channel_descriptors": []any{channel}}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := codec.DecodeInvocation(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.RecordInvocationDelivered(msg); err != nil {
		t.Fatal(err)
	}
	end, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptTerminal(end); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveStdoutEOF(); err != nil {
		t.Fatal(err)
	}
	if err := machine.ObserveProcessExit(true); err != nil {
		t.Fatal(err)
	}
}

func TestCommitmentReconstructionUsesExistingProtocolGate(t *testing.T) {
	c := freezeFixture(t)
	first, err := c.AdmitPhase(context.Background(), "initial")
	if err != nil {
		t.Fatal(err)
	}
	before := first.Locations()
	digest := c.Digest()
	completeSyntheticInitial(t, first)
	second, err := c.AdmitPhase(context.Background(), "reconstruction")
	if err != nil {
		t.Fatal(err)
	}
	if first.Machine() == second.Machine() || second.Locations() != before || c.Digest() != digest {
		t.Fatal("reconstruction changed frozen binding")
	}
	if first.Recheck(context.Background()) != ErrPreflight {
		t.Fatal("old admission still active")
	}
	if err := second.Recheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionRejectsLostCustodyAndFailedProtocol(t *testing.T) {
	for _, kind := range []string{"closed-file", "startup-bypass", "nil-context"} {
		t.Run(kind, func(t *testing.T) {
			c := freezeFixture(t)
			a, err := c.AdmitPhase(context.Background(), "initial")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch kind {
			case "closed-file":
				_ = c.core.files.Close()
			case "startup-bypass":
				if a.Machine().AuthorizeInvocationInput() == nil {
					t.Fatal("input before startup accepted")
				}
			case "nil-context":
				ctx = nil
			}
			if a.Recheck(ctx) == nil || a.Recheck(context.Background()) == nil {
				t.Fatal("failed admission revived")
			}
		})
	}
	var zero FrozenPreflight
	if zero.Digest() != "" || zero.Close() != nil {
		t.Fatal("invalid zero metadata")
	}
	if _, err := zero.AdmitPhase(context.Background(), "initial"); err != ErrPreflight {
		t.Fatal(err)
	}
	var empty PhaseAdmission
	if empty.Recheck(context.Background()) != ErrPreflight {
		t.Fatal("zero admission accepted")
	}
}

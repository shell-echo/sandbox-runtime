//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func runBreakGlassScenarios(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	binding := environment.materials["product-runtime"][0].Binding
	request, revision := submitBreakGlass(t, ctx, environment, binding, gateCredentialAgentID("product-runtime"), 2*time.Minute)
	revision = approveBreakGlass(t, ctx, environment, request, revision, "phase6-approver-a")
	revision = approveBreakGlass(t, ctx, environment, request, revision, "phase6-approver-b")
	capability := issueBreakGlass(t, ctx, environment, request.RequestID, revision)
	if err := breakglass.Deliver(ctx, environment.paths.breakGlassSockets["gateway"], uint32(os.Getuid()), uint32(os.Getgid()), capability); !errors.Is(err, breakglass.ErrUnavailable) {
		t.Fatalf("cross-agent break-glass delivery error=%v", err)
	}
	if err := breakglass.Deliver(ctx, environment.paths.breakGlassSockets["product-runtime"], uint32(os.Getuid()), uint32(os.Getgid()), capability); err != nil {
		t.Fatalf("break-glass consume: %v", err)
	}
	stopGateProcess(t, environment.breakGlassController, 10*time.Second)
	if _, err := os.Lstat(environment.paths.breakGlassControllerSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("break-glass controller socket retained across restart: %v", err)
	}
	startGateBreakGlassController(t, ctx, environment)
	if err := breakglass.Deliver(ctx, environment.paths.breakGlassSockets["product-runtime"], uint32(os.Getuid()), uint32(os.Getgid()), capability); !errors.Is(err, breakglass.ErrConsumed) {
		t.Fatalf("break-glass second consume error=%v", err)
	}

	revokeRequest, revokeRevision := submitBreakGlass(t, ctx, environment, binding, gateCredentialAgentID("product-runtime"), 2*time.Minute)
	revokeRevision = approveBreakGlass(t, ctx, environment, revokeRequest, revokeRevision, "phase6-approver-a")
	revokeRevision = approveBreakGlass(t, ctx, environment, revokeRequest, revokeRevision, "phase6-approver-b")
	revokedCapability := issueBreakGlass(t, ctx, environment, revokeRequest.RequestID, revokeRevision)
	revokeBreakGlass(t, ctx, environment, revokeRequest.RequestID, revokeRevision+1)
	if err := breakglass.Deliver(ctx, environment.paths.breakGlassSockets["product-runtime"], uint32(os.Getuid()), uint32(os.Getgid()), revokedCapability); !errors.Is(err, breakglass.ErrRevoked) {
		t.Fatalf("revoked break-glass delivery error=%v", err)
	}

	expiryRequest, expiryRevision := submitBreakGlass(t, ctx, environment, binding, gateCredentialAgentID("product-runtime"), time.Second)
	expiryRevision = approveBreakGlass(t, ctx, environment, expiryRequest, expiryRevision, "phase6-approver-a")
	expiryRevision = approveBreakGlass(t, ctx, environment, expiryRequest, expiryRevision, "phase6-approver-b")
	expiredCapability := issueBreakGlass(t, ctx, environment, expiryRequest.RequestID, expiryRevision)
	time.Sleep(1100 * time.Millisecond)
	if err := breakglass.Deliver(ctx, environment.paths.breakGlassSockets["product-runtime"], uint32(os.Getuid()), uint32(os.Getgid()), expiredCapability); err == nil {
		t.Fatal("expired break-glass capability was accepted")
	}

	migration := environment.materials["product-migration"][0].Binding
	migrationRequest := newBreakGlassRequest(t, environment, migration, gateCredentialAgentID("product-runtime"), time.Minute)
	if _, err := callBreakGlass(t, ctx, environment, breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &migrationRequest}); !errors.Is(err, breakglass.ErrDenied) {
		t.Fatalf("migration break-glass error=%v", err)
	}
}

func submitBreakGlass(t *testing.T, ctx context.Context, environment *gateEnvironment, binding secretref.Binding, target string, ttl time.Duration) (breakglass.AccessRequest, int64) {
	t.Helper()
	request := newBreakGlassRequest(t, environment, binding, target, ttl)
	response, err := callBreakGlass(t, ctx, environment, breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &request})
	if err != nil {
		t.Fatal(err)
	}
	return request, response.Revision
}

func newBreakGlassRequest(t *testing.T, environment *gateEnvironment, binding secretref.Binding, target string, ttl time.Duration) breakglass.AccessRequest {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	request := breakglass.AccessRequest{RequestID: "bgreq_" + hex.EncodeToString(raw), RequesterID: "phase6-requester", TargetAgentID: target,
		Role: binding.Role, Purpose: binding.Purpose, BindingDigest: binding.Digest(), TenantID: binding.TenantID, Operation: "material.resolve",
		ReasonDigest: gateTextDigest("phase6 emergency reason"), TicketDigest: gateTextDigest("phase6-ticket"), RequestedTTLSeconds: int64(ttl / time.Second),
		Deadline: time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano), JTI: gateJTI(t)}
	request, err := breakglass.NewSignedAccessRequest(request, environment.breakGlassKeys["phase6-requester"])
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func approveBreakGlass(t *testing.T, ctx context.Context, environment *gateEnvironment, request breakglass.AccessRequest, revision int64, approver string) int64 {
	t.Helper()
	approval, err := breakglass.NewSignedApproval(breakglass.Approval{RequestID: request.RequestID, RequestDigest: request.RequestDigest,
		Revision: revision, ApproverID: approver, Deadline: time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano), JTI: gateJTI(t)}, environment.breakGlassKeys[approver])
	if err != nil {
		t.Fatal(err)
	}
	response, err := callBreakGlass(t, ctx, environment, breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.ApproveType, Approval: &approval})
	if err != nil {
		t.Fatal(err)
	}
	return response.Revision
}

func issueBreakGlass(t *testing.T, ctx context.Context, environment *gateEnvironment, requestID string, revision int64) breakglass.Capability {
	t.Helper()
	command, err := breakglass.NewSignedCommand(breakglass.Command{Type: breakglass.CommandIssue, RequestID: requestID, Revision: revision,
		ActorID: "phase6-operator", Deadline: time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano), JTI: gateJTI(t)}, environment.breakGlassKeys["phase6-operator"])
	if err != nil {
		t.Fatal(err)
	}
	response, err := callBreakGlass(t, ctx, environment, breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.IssueType, Command: &command})
	if err != nil || response.Capability == nil {
		t.Fatalf("break-glass issue response=%#v error=%v", response, err)
	}
	return *response.Capability
}

func revokeBreakGlass(t *testing.T, ctx context.Context, environment *gateEnvironment, requestID string, revision int64) {
	t.Helper()
	command, err := breakglass.NewSignedCommand(breakglass.Command{Type: breakglass.CommandRevoke, RequestID: requestID, Revision: revision,
		ActorID: "phase6-operator", Deadline: time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano), JTI: gateJTI(t)}, environment.breakGlassKeys["phase6-operator"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callBreakGlass(t, ctx, environment, breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.RevokeType, Command: &command}); err != nil {
		t.Fatal(err)
	}
}

func callBreakGlass(t *testing.T, ctx context.Context, environment *gateEnvironment, request breakglass.WireRequest) (breakglass.WireResponse, error) {
	t.Helper()
	operationContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return breakglass.Call(operationContext, environment.paths.breakGlassControllerSocket, uint32(os.Getuid()), uint32(os.Getgid()), request)
}

func gateJTI(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	return base64.RawURLEncoding.EncodeToString(value)
}

func gateTextDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

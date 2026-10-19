package codingcontrol

import (
	"context"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type createReadRepository struct {
	create   dockercontrol.CodingCreateAuthority
	commits  int
	observed CreateObservation
}

func (r *createReadRepository) ReadCreateBinding(context.Context, string) (dockercontrol.CodingCreateAuthority, error) {
	return r.create, nil
}
func (r *createReadRepository) CompleteCreateWithObservation(_ context.Context, _ string, o CreateObservation) (lifecycle.Operation, lifecycle.Sandbox, error) {
	r.commits++
	r.observed = o
	return lifecycle.Operation{}, lifecycle.Sandbox{}, nil
}

type createObserverFunc func(context.Context, codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error)

func (f createObserverFunc) Observe(c context.Context, r codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	return f(c, r)
}

func TestCreateReadbackOnlyCommitsExactCompletedObservation(t *testing.T) {
	for _, name := range []string{"completed", "unknown", "released", "not found", "wrong effect", "wrong action", "wrong profile", "wrong operation", "late receipt", "cancel after observe"} {
		t.Run(name, func(t *testing.T) {
			create, cleanup, now := testAuthorities(t)
			repo := &createReadRepository{create: create}
			calls := 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			observer := createObserverFunc(func(_ context.Context, r codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
				calls++
				if r.Action != codingcontrolprotocol.ActionStatus || r.Create != create || r.Cleanup != nil {
					t.Fatal("readback became mutation or changed original")
				}
				response := testResponse(create, cleanup, codingcontrolprotocol.StatusCompleted, now)
				switch name {
				case "unknown":
					response.Status = codingcontrolprotocol.StatusUnknown
					response.CompletionDigest = ""
					response.CompletionEvidenceDigest = ""
				case "released":
					response = testResponse(create, cleanup, codingcontrolprotocol.StatusReleased, now)
				case "not found":
					response = codingcontrolprotocol.Response{Protocol: r.Protocol, Scope: r.Scope, Action: r.Action, Status: codingcontrolprotocol.StatusNotFound, CreateAuthorityDigest: create.Digest(), EffectID: create.EffectID}
				case "wrong effect":
					response.CreateAuthorityDigest = testDigest("0")
				case "wrong action":
					response.Action = codingcontrolprotocol.ActionCreate
				case "late receipt":
					response.UpdatedAt = create.ExpiresAt
				case "cancel after observe":
					cancel()
				}
				return response, nil
			})
			expected := Expected{create.ProfileDigest, create.ControlPolicyDigest, create.PeerPrincipalDigest}
			operationID := create.OperationID
			if name == "wrong profile" {
				expected.ProfileDigest = testDigest("0")
			}
			if name == "wrong operation" {
				operationID = "other-operation"
			}
			c, err := NewCreateReadback(repo, observer, staticClock{create.ExpiresAt.Add(time.Minute)}, expected)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = c.ReconcileCodingCreate(ctx, operationID)
			if name == "completed" {
				if err != nil || repo.commits != 1 || repo.observed.Validate(create, create.ExpiresAt.Add(time.Minute)) != nil {
					t.Fatalf("historical status: %v", err)
				}
			} else if err == nil || repo.commits != 0 {
				t.Fatal("untrusted Ready commit")
			}
			if (name == "wrong profile" || name == "wrong operation") && calls != 0 {
				t.Fatal("crossed binding reached observer")
			}
		})
	}
}

package codingcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

type dispatchRepository struct {
	*testRepository
	reads, finishReads int
	commitErr          error
	cancel             context.CancelFunc
}

func (r *dispatchRepository) ReadBeginBinding(ctx context.Context, id string) (Binding, error) {
	r.reads++
	if r.begun != 0 {
		return Binding{}, ErrObservation
	}
	return r.testRepository.ReadBeginBinding(ctx, id)
}
func (r *dispatchRepository) ReadFinishBinding(context.Context, string) (Binding, error) {
	r.finishReads++
	return Binding{}, errors.New("recovery reads cannot mint permits")
}
func (r *dispatchRepository) BeginWithObservation(ctx context.Context, id string, o CompletedObservation) (dockercontrol.CodingCleanupAuthority, error) {
	if r.cancel != nil {
		r.cancel()
	}
	if r.commitErr != nil {
		return dockercontrol.CodingCleanupAuthority{}, r.commitErr
	}
	return r.testRepository.BeginWithObservation(ctx, id, o)
}

type cleanupDispatcher struct {
	calls    int
	create   dockercontrol.CodingCreateAuthority
	cleanup  dockercontrol.CodingCleanupAuthority
	deadline time.Time
	err      error
}

func (d *cleanupDispatcher) DispatchCodingCleanupAuthority(ctx context.Context, create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority) error {
	d.calls++
	d.create, d.cleanup = create, cleanup
	d.deadline, _ = ctx.Deadline()
	return d.err
}

func TestCleanupDispatchUsesOnlySameCallPermit(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "ack", true: "lost reply"}[lost], func(t *testing.T) {
			create, cleanup, now := testAuthorities(t)
			repo := &dispatchRepository{testRepository: &testRepository{binding: Binding{Create: create, TerminationID: cleanup.CleanupOperationID}, issued: cleanup}}
			observer := &testObserver{response: testResponse(create, cleanup, codingcontrolprotocol.StatusCompleted, now)}
			dispatcher := &cleanupDispatcher{}
			if lost {
				dispatcher.err = errors.New("lost mutation reply")
			}
			c, err := NewWithDispatcher(repo, observer, dispatcher, staticClock{now.Add(2 * time.Second)}, Expected{create.ProfileDigest, create.ControlPolicyDigest, create.PeerPrincipalDigest})
			if err != nil {
				t.Fatal(err)
			}
			err = c.BeginAndDispatch(t.Context(), cleanup.CleanupOperationID)
			if !errors.Is(err, dispatcher.err) || dispatcher.calls != 1 || dispatcher.create != create || dispatcher.cleanup != cleanup || !dispatcher.deadline.Equal(cleanup.ExpiresAt) || repo.finishReads != 0 || repo.begun != 1 {
				t.Fatalf("same-call dispatch: %v / %#v", err, dispatcher)
			}
			if c.BeginAndDispatch(t.Context(), cleanup.CleanupOperationID) == nil || dispatcher.calls != 1 || repo.finishReads != 0 {
				t.Fatal("historical intent dispatched again")
			}
		})
	}
}

func TestCleanupDispatchRejectsUncertainCommitAndChangedPermit(t *testing.T) {
	for _, name := range []string{"commit error", "cancel after commit", "different create", "different termination", "expired", "no dispatcher"} {
		t.Run(name, func(t *testing.T) {
			create, cleanup, now := testAuthorities(t)
			repo := &dispatchRepository{testRepository: &testRepository{binding: Binding{Create: create, TerminationID: cleanup.CleanupOperationID}, issued: cleanup}}
			observer := &testObserver{response: testResponse(create, cleanup, codingcontrolprotocol.StatusCompleted, now)}
			dispatcher := &cleanupDispatcher{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "commit error":
				repo.commitErr = errors.New("commit outcome unknown")
			case "cancel after commit":
				repo.cancel = cancel
			case "different create":
				repo.issued.OriginalAuthorityDigest = testDigest("9")
			case "different termination":
				repo.issued.CleanupOperationID = "other-operation"
			case "expired":
				repo.issued.ExpiresAt = now
			}
			c, err := NewWithDispatcher(repo, observer, dispatcher, staticClock{now.Add(2 * time.Second)}, Expected{create.ProfileDigest, create.ControlPolicyDigest, create.PeerPrincipalDigest})
			if err != nil {
				t.Fatal(err)
			}
			if name == "no dispatcher" {
				c.dispatcher = nil
			}
			if c.BeginAndDispatch(ctx, cleanup.CleanupOperationID) == nil || dispatcher.calls != 0 || repo.finishReads != 0 {
				t.Fatal("untrusted permit dispatched")
			}
		})
	}
}

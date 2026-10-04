//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSlice6EarlyControllerOwnerPreReadinessGoexitNoIssuer(t *testing.T) {
	id := strings.Repeat("a", 64)
	var operations []string
	owner, err := slice6NewEarlyControllerAttachOwner(id,
		func(_ context.Context, args ...string) error {
			operations = append(operations, args[0])
			return nil
		}, func(context.Context) error {
			t.Fatal("unstarted attach was joined")
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		defer func() { finished <- owner.finish() }()
		runtime.Goexit() // models a pre-readiness Fatal without failing this test.
	}()
	select {
	case err := <-finished:
		if err != nil || !slices.Equal(operations, []string{"rm"}) {
			t.Fatalf("pre-readiness owner did not remove exact create: ops=%v err=%v", operations, err)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-readiness guard did not run on Goexit")
	}
	if owner.finish() != nil || !slices.Equal(operations, []string{"rm"}) {
		t.Fatal("early guard retried its one-shot cleanup")
	}
}

func TestSlice6EarlyControllerOwnerAttachJoinHandoffAndFailureNoIssuer(t *testing.T) {
	id := strings.Repeat("b", 64)
	for _, test := range []struct {
		name, fail string
		consume    bool
		handoff    bool
		want       []string
		wantError  bool
	}{
		{"early_failure", "", false, false, []string{"cancel", "stop", "join", "rm"}, false},
		{"already_consumed", "", true, false, []string{"cancel", "rm"}, false},
		{"normal_handoff", "", false, true, nil, false},
		{"stop_error", "stop", false, false, []string{"cancel", "stop", "join", "rm"}, true},
		{"join_error", "join", false, false, []string{"cancel", "stop", "join", "rm"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var operations []string
			owner, err := slice6NewEarlyControllerAttachOwner(id,
				func(_ context.Context, args ...string) error {
					operations = append(operations, args[0])
					if args[0] == test.fail {
						return errors.New("injected exact operation failure")
					}
					return nil
				}, func(context.Context) error {
					operations = append(operations, "join")
					if test.fail == "join" {
						return errors.New("injected missing completion")
					}
					return nil
				})
			if err != nil || owner.attach(func() { operations = append(operations, "cancel") }) != nil {
				t.Fatal("exact controller attach owner unavailable")
			}
			if test.consume && owner.consume() != nil {
				t.Fatal("already-reaped attached command not recorded")
			}
			if test.handoff && owner.handoff() != nil {
				t.Fatal("normal cleanup handoff unavailable")
			}
			err = owner.finish()
			if (err != nil) != test.wantError || !slices.Equal(operations, test.want) {
				t.Fatalf("early owner result drift: ops=%v err=%v", operations, err)
			}
			if owner.finish() != err || !slices.Equal(operations, test.want) {
				t.Fatal("early owner retried one-shot cleanup")
			}
		})
	}
}

func TestSlice6EarlyControllerOwnerExactRestartRetirementNoIssuer(t *testing.T) {
	var operations []string
	owners := make([]*slice6EarlyControllerAttachOwner, 0, 3)
	for index := range 3 {
		id := strings.Repeat(string(rune('a'+index)), 64)
		owner, err := slice6NewEarlyControllerAttachOwner(id,
			func(_ context.Context, args ...string) error {
				operations = append(operations, id+":"+args[0])
				return nil
			}, func(context.Context) error {
				operations = append(operations, id+":join")
				return nil
			})
		if err != nil || owner.attach(func() { operations = append(operations, id+":cancel") }) != nil {
			t.Fatal("replacement exact attach owner unavailable")
		}
		owners = append(owners, owner)
		if index < 2 {
			if owner.consume() != nil || owner.retire() != nil || owner.retire() == nil {
				t.Fatal("consumed replacement could not retire exactly once")
			}
		}
	}
	for index := len(owners) - 1; index >= 0; index-- {
		if err := owners[index].finish(); err != nil {
			t.Fatal(err)
		}
	}
	lastID := strings.Repeat("c", 64)
	if !slices.Equal(operations, []string{lastID + ":cancel", lastID + ":stop",
		lastID + ":join", lastID + ":rm"}) {
		t.Fatalf("retired historical instances were reaped twice or active replacement leaked: %v", operations)
	}
}

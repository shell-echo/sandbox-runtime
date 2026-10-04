//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"time"
)

// Owns one exact controller container only until the normal shutdown guard
// has been registered. It closes the pre-readiness Fatal/Goexit gap; it does
// not create a second terminal-operator or business-cleanup path.
type slice6EarlyControllerAttachOwner struct {
	id        string
	docker    func(context.Context, ...string) error
	join      func(context.Context) error
	cancel    context.CancelFunc
	attached  bool
	consumed  bool
	handedOff bool
	sequence  *slice6CleanupSequence
}

func slice6NewEarlyControllerAttachOwner(id string,
	docker func(context.Context, ...string) error,
	join func(context.Context) error) (*slice6EarlyControllerAttachOwner, error) {
	if len(id) != 64 || !lowerHexSlice6(id) || docker == nil || join == nil {
		return nil, errors.New("early controller exact owner unavailable")
	}
	owner := &slice6EarlyControllerAttachOwner{id: id, docker: docker, join: join}
	owner.sequence = &slice6CleanupSequence{stages: []slice6CleanupStage{
		{"cancel-early-controller-attach", func(context.Context) error {
			if owner.attached && owner.cancel != nil {
				owner.cancel()
			}
			return nil
		}},
		{"stop-early-controller", func(ctx context.Context) error {
			if !owner.attached || owner.consumed {
				return nil
			}
			if err := owner.docker(ctx, "stop", "-t", "5", owner.id); err != nil {
				return errors.New("early controller exact stop unconfirmed")
			}
			return nil
		}},
		{"join-early-controller-attach", func(ctx context.Context) error {
			if !owner.attached || owner.consumed {
				return nil
			}
			if err := owner.join(ctx); err != nil {
				return errors.New("early controller attach join unconfirmed")
			}
			owner.consumed = true
			return nil
		}},
		{"remove-early-controller", func(ctx context.Context) error {
			if err := owner.docker(ctx, "rm", "-f", owner.id); err != nil {
				return errors.New("early controller exact removal unconfirmed")
			}
			return nil
		}},
	}}
	return owner, nil
}

func (owner *slice6EarlyControllerAttachOwner) attach(cancel context.CancelFunc) error {
	if owner == nil || owner.sequence == nil || owner.handedOff || owner.attached || cancel == nil {
		return errors.New("early controller attach ownership unavailable")
	}
	owner.cancel = cancel
	owner.attached = true
	return nil
}

func (owner *slice6EarlyControllerAttachOwner) consume() error {
	if owner == nil || !owner.attached || owner.consumed || owner.handedOff {
		return errors.New("early controller attach completion unavailable")
	}
	owner.consumed = true
	return nil
}

func (owner *slice6EarlyControllerAttachOwner) handoff() error {
	if owner == nil || owner.sequence == nil || !owner.attached || owner.consumed || owner.handedOff {
		return errors.New("early controller normal cleanup handoff unavailable")
	}
	owner.handedOff = true
	return nil
}

// For a controller deliberately replaced during one invocation, normal
// stop/drain and exact rm consume this owner without installing another guard.
func (owner *slice6EarlyControllerAttachOwner) retire() error {
	if owner == nil || owner.sequence == nil || !owner.attached || !owner.consumed || owner.handedOff {
		return errors.New("exact controller retirement unavailable")
	}
	owner.handedOff = true
	return nil
}

func (owner *slice6EarlyControllerAttachOwner) finish() error {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	return owner.finishWithContext(ctx)
}

func (owner *slice6EarlyControllerAttachOwner) finishWithContext(ctx context.Context) error {
	if owner == nil || owner.sequence == nil {
		return errors.New("early controller exact cleanup unavailable")
	}
	if owner.handedOff {
		return nil
	}
	return owner.sequence.RunContext(ctx)
}

package rediscapacity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestActionHistoryCheckpointValidationAndRedaction(t *testing.T) {
	token := strings.Repeat("a", actionHistoryTokenBytes*2)
	checkpoint, err := NewActionHistoryCheckpoint(7, token)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Sequence() != 7 || checkpoint.OpaqueToken() != token {
		t.Fatalf("checkpoint = sequence %d token %q", checkpoint.Sequence(), checkpoint.OpaqueToken())
	}
	for _, formatted := range []string{fmt.Sprint(checkpoint), fmt.Sprintf("%+v", checkpoint), fmt.Sprintf("%#v", checkpoint)} {
		if strings.Contains(formatted, token) || !strings.Contains(formatted, "redacted") {
			t.Fatalf("formatted checkpoint exposed token: %s", formatted)
		}
	}
	for _, invalid := range []struct {
		sequence int64
		token    string
	}{
		{-1, token},
		{maxLuaExactInteger + 1, token},
		{0, strings.Repeat("A", actionHistoryTokenBytes*2)},
		{0, strings.Repeat("a", actionHistoryTokenBytes*2-1)},
	} {
		if _, err := NewActionHistoryCheckpoint(invalid.sequence, invalid.token); !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("NewActionHistoryCheckpoint(%d, %q) error = %v", invalid.sequence, invalid.token, err)
		}
	}
}

func TestFileActionHistoryWitnessLifecycleAndReconstruction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "independent", "action-history.json")
	witness, err := OpenFileActionHistoryWitness(path)
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("b", 64)
	initial, _ := NewActionHistoryCheckpoint(0, strings.Repeat("c", 64))
	next, _ := NewActionHistoryCheckpoint(1, strings.Repeat("d", 64))

	if _, err := witness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("initial Load() error = %v", err)
	}
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatal(err)
	}
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatalf("idempotent Provision() error = %v", err)
	}
	if err := witness.CompareAndSwap(context.Background(), policy, initial, next); err != nil {
		t.Fatal(err)
	}
	if current, err := witness.Load(context.Background(), policy); err != nil || !current.Equal(next) {
		t.Fatalf("Load() = %v, %v; want next checkpoint", current, err)
	}
	if err := witness.CompareAndSwap(context.Background(), policy, initial, next); !errors.Is(err, ErrActionHistoryConflict) {
		t.Fatalf("stale CompareAndSwap() error = %v", err)
	}
	if _, err := OpenFileActionHistoryWitness(path); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("concurrent OpenFileActionHistoryWitness() error = %v", err)
	}
	if err := witness.Close(); err != nil {
		t.Fatal(err)
	}

	reconstructed, err := OpenFileActionHistoryWitness(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reconstructed.Close() })
	if current, err := reconstructed.Load(context.Background(), policy); err != nil || !current.Equal(next) {
		t.Fatalf("reconstructed Load() = %v, %v; want next checkpoint", current, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("witness mode = %v, %v; want 0600", info.Mode(), err)
	}
}

func TestFileActionHistoryWitnessFailsClosed(t *testing.T) {
	policy := strings.Repeat("e", 64)
	initial, _ := NewActionHistoryCheckpoint(0, strings.Repeat("f", 64))
	next, _ := NewActionHistoryCheckpoint(1, strings.Repeat("1", 64))

	t.Run("invalid transitions and context", func(t *testing.T) {
		witness, err := OpenFileActionHistoryWitness(filepath.Join(t.TempDir(), "witness.json"))
		if err != nil {
			t.Fatal(err)
		}
		defer witness.Close()
		if err := witness.Provision(context.Background(), policy, next); !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("nonzero Provision() error = %v", err)
		}
		if err := witness.Provision(context.Background(), policy, initial); err != nil {
			t.Fatal(err)
		}
		jump, _ := NewActionHistoryCheckpoint(2, strings.Repeat("2", 64))
		if err := witness.CompareAndSwap(context.Background(), policy, initial, jump); !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("jump CompareAndSwap() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := witness.Load(ctx, policy); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("canceled Load() error = %v", err)
		}
		if err := witness.Provision(ctx, policy, initial); !errors.Is(err, context.Canceled) ||
			!errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("canceled Provision() error = %v", err)
		}
		if err := witness.CompareAndSwap(ctx, policy, initial, next); !errors.Is(err, context.Canceled) ||
			!errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("canceled CompareAndSwap() error = %v", err)
		}
		if current, err := witness.Load(context.Background(), policy); err != nil || !current.Equal(initial) {
			t.Fatalf("Load() after canceled transition = %v, %v; want initial checkpoint", current, err)
		}
		if err := witness.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := witness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("closed Load() error = %v", err)
		}
	})

	for _, test := range []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"unknown field", `{"version":1,"policy_fingerprint":"` + policy + `","sequence":0,"token":"` + initial.token + `","extra":true}` + "\n", 0o600},
		{"duplicate field", `{"version":1,"version":1,"policy_fingerprint":"` + policy + `","sequence":0,"token":"` + initial.token + `"}` + "\n", 0o600},
		{"multiple values", `{"version":1,"policy_fingerprint":"` + policy + `","sequence":0,"token":"` + initial.token + `"} {}` + "\n", 0o600},
		{"invalid checkpoint", `{"version":1,"policy_fingerprint":"` + policy + `","sequence":-1,"token":"` + initial.token + `"}` + "\n", 0o600},
		{"oversized", strings.Repeat("x", maxActionHistoryFileSize+1), 0o600},
		{"insecure mode", `{"version":1,"policy_fingerprint":"` + policy + `","sequence":0,"token":"` + initial.token + `"}` + "\n", 0o644},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "witness.json")
			if err := os.WriteFile(path, []byte(test.content), test.mode); err != nil {
				t.Fatal(err)
			}
			if witness, err := OpenFileActionHistoryWitness(path); witness != nil || !errors.Is(err, ErrActionHistoryUnavailable) {
				t.Fatalf("OpenFileActionHistoryWitness() = %#v, %v", witness, err)
			}
		})
	}

	t.Run("symlink state", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.json")
		path := filepath.Join(directory, "witness.json")
		content := `{"version":1,"policy_fingerprint":"` + policy + `","sequence":0,"token":"` + initial.token + `"}` + "\n"
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if witness, err := OpenFileActionHistoryWitness(path); witness != nil || !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("OpenFileActionHistoryWitness(symlink) = %#v, %v", witness, err)
		}
	})

	t.Run("insecure lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "witness.json")
		if err := os.WriteFile(path+".lock", nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if witness, err := OpenFileActionHistoryWitness(path); witness != nil || !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("OpenFileActionHistoryWitness(insecure lock) = %#v, %v", witness, err)
		}
	})

	t.Run("symlink lock", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "witness.json")
		target := filepath.Join(directory, "lock-target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+".lock"); err != nil {
			t.Fatal(err)
		}
		if witness, err := OpenFileActionHistoryWitness(path); witness != nil || !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("OpenFileActionHistoryWitness(symlink lock) = %#v, %v", witness, err)
		}
	})

	t.Run("non-regular state", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "witness.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if witness, err := OpenFileActionHistoryWitness(path); witness != nil || !errors.Is(err, ErrActionHistoryUnavailable) {
			t.Fatalf("OpenFileActionHistoryWitness(directory) = %#v, %v", witness, err)
		}
	})
}

func TestWitnessedActionFencerRequiresWitnessAndPreservesV1Identity(t *testing.T) {
	options := testOptions(t)
	options.Namespace = "private-witnessed-action-namespace"
	capacity, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	var nilWitness *FileActionHistoryWitness
	if fencer, err := NewWitnessedActionFencer(capacity, nilWitness); fencer != nil || err != gateway.ErrDownstreamUnavailable {
		t.Fatalf("NewWitnessedActionFencer(typed nil) = %#v, %v", fencer, err)
	}
	witness, err := OpenFileActionHistoryWitness(filepath.Join(t.TempDir(), "witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer witness.Close()
	fencer, err := NewWitnessedActionFencer(capacity, witness)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fencer.Descriptor()
	if descriptor.PolicyFormat != witnessedActionPolicyFormat || descriptor.CheckpointFormat != witnessedActionCheckpointFormat ||
		descriptor.MaxHistoryEntries != maxWitnessedActionHistoryEntries || descriptor.PolicyFingerprint == "" ||
		descriptor.ProvisionScript == "" || descriptor.AuthorizeScript == "" {
		t.Fatalf("Descriptor() = %#v", descriptor)
	}
	formatted := fmt.Sprintf("%+v", descriptor)
	for _, forbidden := range []string{options.Namespace, capacity.keyTag, fencer.policyKey, fencer.stateKey} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("Descriptor() exposed private state %q: %s", forbidden, formatted)
		}
	}
	legacy, err := NewActionFencer(capacity)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Descriptor().PolicyFormat != actionPolicyFormat || legacy.Descriptor().PolicyFingerprint == descriptor.PolicyFingerprint {
		t.Fatal("witnessed fencer changed or reused the v1 action policy identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	claim, claimErr := gateway.NewDownstreamFence("v1.YQ")
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	decision, err := fencer.AuthorizeAction(ctx, gateway.DownstreamFenceSubject{}, claim, gateway.MinDownstreamActionWindow)
	if decision.Activated || !errors.Is(err, context.Canceled) || !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("canceled AuthorizeAction() = %#v, %v", decision, err)
	}
	deadlineFencer, err := NewWitnessedActionFencer(capacity, errorActionHistoryWitness{err: context.DeadlineExceeded})
	if err != nil {
		t.Fatal(err)
	}
	if err := deadlineFencer.Verify(context.Background()); !errors.Is(err, context.DeadlineExceeded) ||
		!errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("Verify() witness deadline error = %v", err)
	}
}

type errorActionHistoryWitness struct {
	err error
}

func (w errorActionHistoryWitness) Load(context.Context, string) (ActionHistoryCheckpoint, error) {
	return ActionHistoryCheckpoint{}, w.err
}

func (w errorActionHistoryWitness) Provision(context.Context, string, ActionHistoryCheckpoint) error {
	return w.err
}

func (w errorActionHistoryWitness) CompareAndSwap(
	context.Context,
	string,
	ActionHistoryCheckpoint,
	ActionHistoryCheckpoint,
) error {
	return w.err
}

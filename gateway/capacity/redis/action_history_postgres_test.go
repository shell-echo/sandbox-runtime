package rediscapacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestPostgresActionHistoryWitnessLifecycle(t *testing.T) {
	store := newMemoryPostgresActionHistoryStore()
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	witness, err := newPostgresActionHistoryWitness(capacity, store, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("a", 64)
	initial := mustActionHistoryCheckpoint(t, 0, "b")
	alternate := mustActionHistoryCheckpoint(t, 0, "c")
	next := mustActionHistoryCheckpoint(t, 1, "d")

	if _, err := witness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("initial Load() error = %v", err)
	}
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatal(err)
	}
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatalf("idempotent Provision() error = %v", err)
	}
	if err := witness.Provision(context.Background(), policy, alternate); !errors.Is(err, ErrActionHistoryConflict) {
		t.Fatalf("conflicting Provision() error = %v", err)
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
}

func TestPostgresActionHistoryWitnessSeparatesCapacityNamespaces(t *testing.T) {
	store := newMemoryPostgresActionHistoryStore()
	firstOptions := testOptions(t)
	firstOptions.Namespace = "postgres-witness-namespace-a"
	secondOptions := testOptions(t)
	secondOptions.Namespace = "postgres-witness-namespace-b"
	firstCapacity, err := New(firstOptions)
	if err != nil {
		t.Fatal(err)
	}
	secondCapacity, err := New(secondOptions)
	if err != nil {
		t.Fatal(err)
	}
	if firstCapacity.Descriptor().PolicyFingerprint != secondCapacity.Descriptor().PolicyFingerprint {
		t.Fatal("test capacities do not share the same policy fingerprint")
	}
	first, err := newPostgresActionHistoryWitness(firstCapacity, store, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPostgresActionHistoryWitness(secondCapacity, store, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("e", 64)
	firstCheckpoint := mustActionHistoryCheckpoint(t, 0, "f")
	secondCheckpoint := mustActionHistoryCheckpoint(t, 0, "1")
	if err := first.Provision(context.Background(), policy, firstCheckpoint); err != nil {
		t.Fatal(err)
	}
	if err := second.Provision(context.Background(), policy, secondCheckpoint); err != nil {
		t.Fatal(err)
	}
	if current, err := first.Load(context.Background(), policy); err != nil || !current.Equal(firstCheckpoint) {
		t.Fatalf("first Load() = %v, %v", current, err)
	}
	if current, err := second.Load(context.Background(), policy); err != nil || !current.Equal(secondCheckpoint) {
		t.Fatalf("second Load() = %v, %v", current, err)
	}
	if bytes.Equal(first.namespaceFingerprint[:], second.namespaceFingerprint[:]) {
		t.Fatal("distinct capacity namespaces selected the same witness scope")
	}
	for _, formatted := range []string{
		fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first),
		fmt.Sprintf("%+v", second), fmt.Sprintf("%#v", second),
	} {
		if strings.Contains(formatted, firstOptions.Namespace) || strings.Contains(formatted, secondOptions.Namespace) ||
			strings.Contains(formatted, firstCapacity.keyTag) || strings.Contains(formatted, secondCapacity.keyTag) ||
			!strings.Contains(formatted, "redacted") {
			t.Fatalf("witness exposed its capacity scope: %s", formatted)
		}
	}
}

func TestPostgresActionHistoryWitnessRejectsInvalidConfigurationAndCalls(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryPostgresActionHistoryStore()
	for _, test := range []struct {
		name     string
		capacity *Capacity
		store    postgresActionHistoryStore
		timeout  time.Duration
	}{
		{name: "nil capacity", store: store, timeout: 100 * time.Millisecond},
		{name: "nil store", capacity: capacity, timeout: 100 * time.Millisecond},
		{name: "short timeout", capacity: capacity, store: store, timeout: MinOperationTimeout - time.Millisecond},
		{name: "long timeout", capacity: capacity, store: store, timeout: MaxOperationTimeout + time.Millisecond},
		{name: "fractional timeout", capacity: capacity, store: store, timeout: 100*time.Millisecond + time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			witness, err := newPostgresActionHistoryWitness(test.capacity, test.store, test.timeout)
			if witness != nil || !errors.Is(err, gateway.ErrInvalidRequest) {
				t.Fatalf("newPostgresActionHistoryWitness() = %#v, %v", witness, err)
			}
		})
	}
	if witness, err := NewPostgresActionHistoryWitness(PostgresActionHistoryWitnessOptions{
		Capacity: capacity, OperationTimeout: 100 * time.Millisecond,
	}); witness != nil || !errors.Is(err, gateway.ErrInvalidRequest) {
		t.Fatalf("NewPostgresActionHistoryWitness(nil pool) = %#v, %v", witness, err)
	}

	witness, err := newPostgresActionHistoryWitness(capacity, store, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("2", 64)
	initial := mustActionHistoryCheckpoint(t, 0, "3")
	next := mustActionHistoryCheckpoint(t, 1, "4")
	jump := mustActionHistoryCheckpoint(t, 2, "5")
	if err := witness.CompareAndSwap(context.Background(), policy, initial, next); !errors.Is(err, ErrActionHistoryUnavailable) ||
		errors.Is(err, ErrActionHistoryConflict) {
		t.Fatalf("missing CompareAndSwap() error = %v", err)
	}
	if err := witness.Provision(context.Background(), policy, next); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("nonzero Provision() error = %v", err)
	}
	if err := witness.Provision(context.Background(), policy, initial); err != nil {
		t.Fatal(err)
	}
	if err := witness.CompareAndSwap(context.Background(), policy, initial, jump); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("jump CompareAndSwap() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := witness.Load(ctx, policy); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("canceled Load() error = %v", err)
	}
	if err := witness.CompareAndSwap(ctx, policy, initial, next); !errors.Is(err, context.Canceled) ||
		!errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("canceled CompareAndSwap() error = %v", err)
	}
	if _, err := witness.Load(context.Background(), "not-a-fingerprint"); !errors.Is(err, ErrActionHistoryUnavailable) {
		t.Fatalf("invalid policy Load() error = %v", err)
	}
}

func TestPostgresActionHistoryWitnessBoundsAndRedactsStoreFailures(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("6", 64)
	secret := "postgres://runtime:private-password@database.internal/witness"
	failing := &errorPostgresActionHistoryStore{err: errors.New(secret + " SELECT token FROM private_table")}
	witness, err := newPostgresActionHistoryWitness(capacity, failing, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryUnavailable) ||
		strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "SELECT token") {
		t.Fatalf("Load() exposed backend detail: %v", err)
	}
	initial := mustActionHistoryCheckpoint(t, 0, "7")
	if err := witness.Provision(context.Background(), policy, initial); !errors.Is(err, ErrActionHistoryUnavailable) ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("Provision() exposed backend detail: %v", err)
	}
	next := mustActionHistoryCheckpoint(t, 1, "8")
	if err := witness.CompareAndSwap(context.Background(), policy, initial, next); !errors.Is(err, ErrActionHistoryUnavailable) ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("CompareAndSwap() exposed backend detail: %v", err)
	}

	malformed := newMemoryPostgresActionHistoryStore()
	witness, err = newPostgresActionHistoryWitness(capacity, malformed, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	malformed.put(witness.namespaceFingerprint[:], mustDecodeActionHistoryFingerprint(t, policy), postgresActionHistoryRow{
		version: postgresActionHistoryWitnessFormatVersion + 1, sequence: 0, token: []byte{1},
	})
	if _, err := witness.Load(context.Background(), policy); !errors.Is(err, ErrActionHistoryUnavailable) ||
		errors.Is(err, ErrActionHistoryNotProvisioned) {
		t.Fatalf("malformed Load() error = %v", err)
	}
}

func TestPostgresActionHistoryWitnessEnforcesOperationTimeout(t *testing.T) {
	capacity, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("9", 64)
	initial := mustActionHistoryCheckpoint(t, 0, "a")
	next := mustActionHistoryCheckpoint(t, 1, "b")
	for _, test := range []struct {
		name string
		call func(*PostgresActionHistoryWitness) error
	}{
		{name: "load", call: func(witness *PostgresActionHistoryWitness) error {
			_, err := witness.Load(context.Background(), policy)
			return err
		}},
		{name: "provision", call: func(witness *PostgresActionHistoryWitness) error {
			return witness.Provision(context.Background(), policy, initial)
		}},
		{name: "compare and swap", call: func(witness *PostgresActionHistoryWitness) error {
			return witness.CompareAndSwap(context.Background(), policy, initial, next)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			witness, err := newPostgresActionHistoryWitness(capacity, blockingPostgresActionHistoryStore{}, MinOperationTimeout)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err = test.call(witness)
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrActionHistoryUnavailable) {
				t.Fatalf("operation error = %v; want bounded deadline", err)
			}
			if elapsed := time.Since(started); elapsed < MinOperationTimeout || elapsed > 4*MinOperationTimeout {
				t.Fatalf("operation elapsed = %s; want bounded operation", elapsed)
			}
		})
	}
}

func TestExactlyOnePostgresRow(t *testing.T) {
	for _, test := range []struct {
		tag  string
		want bool
		err  bool
	}{
		{tag: "UPDATE 0"},
		{tag: "UPDATE 1", want: true},
		{tag: "UPDATE 2", err: true},
	} {
		got, err := exactlyOnePostgresRow(pgconn.NewCommandTag(test.tag), nil)
		if got != test.want || (err != nil) != test.err {
			t.Fatalf("exactlyOnePostgresRow(%q) = %v, %v", test.tag, got, err)
		}
	}
}

type postgresActionHistoryRow struct {
	version  int16
	sequence int64
	token    []byte
}

type memoryPostgresActionHistoryStore struct {
	mu   sync.Mutex
	rows map[string]postgresActionHistoryRow
}

func newMemoryPostgresActionHistoryStore() *memoryPostgresActionHistoryStore {
	return &memoryPostgresActionHistoryStore{rows: make(map[string]postgresActionHistoryRow)}
}

func (s *memoryPostgresActionHistoryStore) load(
	_ context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
) (int16, int64, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[postgresActionHistoryRowKey(namespaceFingerprint, policyFingerprint)]
	if !ok {
		return 0, 0, nil, pgx.ErrNoRows
	}
	return row.version, row.sequence, bytes.Clone(row.token), nil
}

func (s *memoryPostgresActionHistoryStore) provision(
	_ context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
	version int16,
	sequence int64,
	token []byte,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := postgresActionHistoryRowKey(namespaceFingerprint, policyFingerprint)
	if _, ok := s.rows[key]; ok {
		return false, nil
	}
	s.rows[key] = postgresActionHistoryRow{version: version, sequence: sequence, token: bytes.Clone(token)}
	return true, nil
}

func (s *memoryPostgresActionHistoryStore) compareAndSwap(
	_ context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
	version int16,
	replacementSequence int64,
	replacementToken []byte,
	previousSequence int64,
	previousToken []byte,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := postgresActionHistoryRowKey(namespaceFingerprint, policyFingerprint)
	row, ok := s.rows[key]
	if !ok || row.version != version || row.sequence != previousSequence || !bytes.Equal(row.token, previousToken) {
		return false, nil
	}
	s.rows[key] = postgresActionHistoryRow{
		version: version, sequence: replacementSequence, token: bytes.Clone(replacementToken),
	}
	return true, nil
}

func (s *memoryPostgresActionHistoryStore) put(
	namespaceFingerprint []byte,
	policyFingerprint []byte,
	row postgresActionHistoryRow,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row.token = bytes.Clone(row.token)
	s.rows[postgresActionHistoryRowKey(namespaceFingerprint, policyFingerprint)] = row
}

func postgresActionHistoryRowKey(namespaceFingerprint, policyFingerprint []byte) string {
	return string(namespaceFingerprint) + string(policyFingerprint)
}

type errorPostgresActionHistoryStore struct {
	err error
}

func (s *errorPostgresActionHistoryStore) load(
	context.Context,
	[]byte,
	[]byte,
) (int16, int64, []byte, error) {
	return 0, 0, nil, s.err
}

func (s *errorPostgresActionHistoryStore) provision(
	context.Context,
	[]byte,
	[]byte,
	int16,
	int64,
	[]byte,
) (bool, error) {
	return false, s.err
}

func (s *errorPostgresActionHistoryStore) compareAndSwap(
	context.Context,
	[]byte,
	[]byte,
	int16,
	int64,
	[]byte,
	int64,
	[]byte,
) (bool, error) {
	return false, s.err
}

type blockingPostgresActionHistoryStore struct{}

func (blockingPostgresActionHistoryStore) load(ctx context.Context, _ []byte, _ []byte) (int16, int64, []byte, error) {
	<-ctx.Done()
	return 0, 0, nil, ctx.Err()
}

func (blockingPostgresActionHistoryStore) provision(
	ctx context.Context,
	_ []byte,
	_ []byte,
	_ int16,
	_ int64,
	_ []byte,
) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func (blockingPostgresActionHistoryStore) compareAndSwap(
	ctx context.Context,
	_ []byte,
	_ []byte,
	_ int16,
	_ int64,
	_ []byte,
	_ int64,
	_ []byte,
) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func mustActionHistoryCheckpoint(t *testing.T, sequence int64, tokenCharacter string) ActionHistoryCheckpoint {
	t.Helper()
	checkpoint, err := NewActionHistoryCheckpoint(sequence, strings.Repeat(tokenCharacter, 64))
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func mustDecodeActionHistoryFingerprint(t *testing.T, value string) []byte {
	t.Helper()
	fingerprint, err := decodeActionHistoryFingerprint(value)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint[:]
}

var _ postgresActionHistoryStore = (*memoryPostgresActionHistoryStore)(nil)
var _ postgresActionHistoryStore = (*errorPostgresActionHistoryStore)(nil)
var _ postgresActionHistoryStore = blockingPostgresActionHistoryStore{}

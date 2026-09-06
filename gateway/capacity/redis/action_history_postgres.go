package rediscapacity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	postgresActionHistoryWitnessFormatVersion int16 = 1

	postgresActionHistoryLoadQuery = `SELECT format_version, sequence, token
FROM sandbox_runtime.action_history_witnesses
WHERE namespace_fingerprint = $1 AND policy_fingerprint = $2`

	postgresActionHistoryProvisionQuery = `WITH durability AS MATERIALIZED (
    SELECT set_config('synchronous_commit', 'on', true)
)
INSERT INTO sandbox_runtime.action_history_witnesses
    (namespace_fingerprint, policy_fingerprint, format_version, sequence, token)
SELECT $1, $2, $3, $4, $5 FROM durability
ON CONFLICT (namespace_fingerprint, policy_fingerprint) DO NOTHING`

	postgresActionHistoryCompareAndSwapQuery = `WITH durability AS MATERIALIZED (
    SELECT set_config('synchronous_commit', 'on', true)
)
UPDATE sandbox_runtime.action_history_witnesses AS witness
SET sequence = $3, token = $4, updated_at = clock_timestamp()
FROM durability
WHERE witness.namespace_fingerprint = $1 AND witness.policy_fingerprint = $2
  AND witness.format_version = $5 AND witness.sequence = $6 AND witness.token = $7`
)

// PostgresActionHistoryWitnessOptions binds a PostgreSQL witness to the exact
// Redis capacity namespace without exposing that namespace or its key tag.
type PostgresActionHistoryWitnessOptions struct {
	Capacity         *Capacity
	Pool             *pgxpool.Pool
	OperationTimeout time.Duration
}

// PostgresActionHistoryWitness stores the v2 action checkpoint in PostgreSQL.
// The database must be outside the Redis snapshot, restore, and failure domain.
type PostgresActionHistoryWitness struct {
	store                postgresActionHistoryStore
	namespaceFingerprint [actionHistoryTokenBytes]byte
	operationTimeout     time.Duration
}

type postgresActionHistoryStore interface {
	load(context.Context, []byte, []byte) (int16, int64, []byte, error)
	provision(context.Context, []byte, []byte, int16, int64, []byte) (bool, error)
	compareAndSwap(context.Context, []byte, []byte, int16, int64, []byte, int64, []byte) (bool, error)
}

type pgxActionHistoryStore struct {
	pool *pgxpool.Pool
}

func (w *PostgresActionHistoryWitness) String() string {
	return "postgres-action-history-witness(scope=[redacted])"
}

func (w *PostgresActionHistoryWitness) GoString() string {
	return "rediscapacity.PostgresActionHistoryWitness{scope:[redacted]}"
}

func NewPostgresActionHistoryWitness(options PostgresActionHistoryWitnessOptions) (*PostgresActionHistoryWitness, error) {
	if options.Pool == nil {
		return nil, fmt.Errorf("%w: PostgreSQL witness pool", gateway.ErrInvalidRequest)
	}
	return newPostgresActionHistoryWitness(options.Capacity, &pgxActionHistoryStore{pool: options.Pool}, options.OperationTimeout)
}

func newPostgresActionHistoryWitness(
	capacity *Capacity,
	store postgresActionHistoryStore,
	operationTimeout time.Duration,
) (*PostgresActionHistoryWitness, error) {
	if capacity == nil || capacity.client == nil || len(capacity.keys) != 3 || len(capacity.policyArgs) != 9 ||
		capacity.keyTag == "" || nilInterface(store) {
		return nil, fmt.Errorf("%w: PostgreSQL witness dependencies", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(operationTimeout) || operationTimeout < MinOperationTimeout || operationTimeout > MaxOperationTimeout {
		return nil, fmt.Errorf("%w: PostgreSQL witness operation timeout", gateway.ErrInvalidRequest)
	}
	namespaceFingerprint, err := decodeActionHistoryFingerprint(capacity.keyTag)
	if err != nil {
		return nil, fmt.Errorf("%w: PostgreSQL witness namespace", gateway.ErrInvalidRequest)
	}
	return &PostgresActionHistoryWitness{
		store: store, namespaceFingerprint: namespaceFingerprint, operationTimeout: operationTimeout,
	}, nil
}

func (w *PostgresActionHistoryWitness) Load(
	ctx context.Context,
	policyFingerprint string,
) (ActionHistoryCheckpoint, error) {
	policy, err := w.validateCall(ctx, policyFingerprint)
	if err != nil {
		return ActionHistoryCheckpoint{}, err
	}
	opCtx, cancel := context.WithTimeout(ctx, w.operationTimeout)
	defer cancel()
	checkpoint, err := w.load(opCtx, policy)
	if err == nil {
		return checkpoint, nil
	}
	if contextErr := postgresActionHistoryContextError(ctx, opCtx, err); contextErr != nil {
		return ActionHistoryCheckpoint{}, contextErr
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ActionHistoryCheckpoint{}, ErrActionHistoryNotProvisioned
	}
	return ActionHistoryCheckpoint{}, postgresActionHistoryUnavailable("load")
}

func (w *PostgresActionHistoryWitness) Provision(
	ctx context.Context,
	policyFingerprint string,
	initial ActionHistoryCheckpoint,
) error {
	policy, err := w.validateCall(ctx, policyFingerprint)
	if err != nil {
		return err
	}
	if initial.validate() != nil || initial.sequence != 0 {
		return ErrActionHistoryUnavailable
	}
	token, err := decodeActionHistoryFingerprint(initial.token)
	if err != nil {
		return ErrActionHistoryUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, w.operationTimeout)
	defer cancel()
	inserted, err := w.store.provision(
		opCtx, w.namespaceFingerprint[:], policy[:], postgresActionHistoryWitnessFormatVersion,
		initial.sequence, token[:],
	)
	if err != nil {
		if contextErr := postgresActionHistoryContextError(ctx, opCtx, err); contextErr != nil {
			return contextErr
		}
		return postgresActionHistoryUnavailable("provision")
	}
	if inserted {
		return nil
	}
	current, err := w.load(opCtx, policy)
	if err != nil {
		if contextErr := postgresActionHistoryContextError(ctx, opCtx, err); contextErr != nil {
			return contextErr
		}
		return postgresActionHistoryUnavailable("provision verification")
	}
	if current.Equal(initial) {
		return nil
	}
	return ErrActionHistoryConflict
}

func (w *PostgresActionHistoryWitness) CompareAndSwap(
	ctx context.Context,
	policyFingerprint string,
	previous ActionHistoryCheckpoint,
	replacement ActionHistoryCheckpoint,
) error {
	policy, err := w.validateCall(ctx, policyFingerprint)
	if err != nil {
		return err
	}
	if previous.validate() != nil || replacement.validate() != nil ||
		replacement.sequence != previous.sequence+1 || replacement.token == previous.token {
		return ErrActionHistoryUnavailable
	}
	previousToken, previousErr := decodeActionHistoryFingerprint(previous.token)
	replacementToken, replacementErr := decodeActionHistoryFingerprint(replacement.token)
	if previousErr != nil || replacementErr != nil {
		return ErrActionHistoryUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, w.operationTimeout)
	defer cancel()
	updated, err := w.store.compareAndSwap(
		opCtx, w.namespaceFingerprint[:], policy[:], postgresActionHistoryWitnessFormatVersion,
		replacement.sequence, replacementToken[:], previous.sequence, previousToken[:],
	)
	if err != nil {
		if contextErr := postgresActionHistoryContextError(ctx, opCtx, err); contextErr != nil {
			return contextErr
		}
		return postgresActionHistoryUnavailable("compare and swap")
	}
	if updated {
		return nil
	}
	if _, err := w.load(opCtx, policy); err != nil {
		if contextErr := postgresActionHistoryContextError(ctx, opCtx, err); contextErr != nil {
			return contextErr
		}
		return postgresActionHistoryUnavailable("compare and swap verification")
	}
	return ErrActionHistoryConflict
}

func (w *PostgresActionHistoryWitness) validateCall(
	ctx context.Context,
	policyFingerprint string,
) ([actionHistoryTokenBytes]byte, error) {
	if w == nil || nilInterface(w.store) || w.operationTimeout == 0 {
		return [actionHistoryTokenBytes]byte{}, ErrActionHistoryUnavailable
	}
	if err := validateActionHistoryCall(ctx, policyFingerprint); err != nil {
		return [actionHistoryTokenBytes]byte{}, err
	}
	policy, err := decodeActionHistoryFingerprint(policyFingerprint)
	if err != nil {
		return [actionHistoryTokenBytes]byte{}, ErrActionHistoryUnavailable
	}
	return policy, nil
}

func (w *PostgresActionHistoryWitness) load(
	ctx context.Context,
	policy [actionHistoryTokenBytes]byte,
) (ActionHistoryCheckpoint, error) {
	version, sequence, token, err := w.store.load(ctx, w.namespaceFingerprint[:], policy[:])
	if err != nil {
		return ActionHistoryCheckpoint{}, err
	}
	if version != postgresActionHistoryWitnessFormatVersion || len(token) != actionHistoryTokenBytes {
		return ActionHistoryCheckpoint{}, ErrActionHistoryUnavailable
	}
	checkpoint, err := NewActionHistoryCheckpoint(sequence, hex.EncodeToString(token))
	if err != nil {
		return ActionHistoryCheckpoint{}, ErrActionHistoryUnavailable
	}
	return checkpoint, nil
}

func (s *pgxActionHistoryStore) load(
	ctx context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
) (int16, int64, []byte, error) {
	var version int16
	var sequence int64
	var token []byte
	err := s.pool.QueryRow(ctx, postgresActionHistoryLoadQuery, namespaceFingerprint, policyFingerprint).
		Scan(&version, &sequence, &token)
	return version, sequence, token, err
}

func (s *pgxActionHistoryStore) provision(
	ctx context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
	version int16,
	sequence int64,
	token []byte,
) (bool, error) {
	tag, err := s.pool.Exec(ctx, postgresActionHistoryProvisionQuery,
		namespaceFingerprint, policyFingerprint, version, sequence, token)
	return exactlyOnePostgresRow(tag, err)
}

func (s *pgxActionHistoryStore) compareAndSwap(
	ctx context.Context,
	namespaceFingerprint []byte,
	policyFingerprint []byte,
	version int16,
	replacementSequence int64,
	replacementToken []byte,
	previousSequence int64,
	previousToken []byte,
) (bool, error) {
	tag, err := s.pool.Exec(ctx, postgresActionHistoryCompareAndSwapQuery,
		namespaceFingerprint, policyFingerprint, replacementSequence, replacementToken,
		version, previousSequence, previousToken)
	return exactlyOnePostgresRow(tag, err)
}

func exactlyOnePostgresRow(tag pgconn.CommandTag, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	switch tag.RowsAffected() {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("PostgreSQL witness mutation affected an invalid row count")
	}
}

func decodeActionHistoryFingerprint(value string) ([actionHistoryTokenBytes]byte, error) {
	var fingerprint [actionHistoryTokenBytes]byte
	if !actionHistoryTokenPattern.MatchString(value) {
		return fingerprint, ErrActionHistoryUnavailable
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(fingerprint) {
		return fingerprint, ErrActionHistoryUnavailable
	}
	copy(fingerprint[:], decoded)
	return fingerprint, nil
}

func postgresActionHistoryContextError(parent, operation context.Context, cause error) error {
	if err := parent.Err(); err != nil {
		return errors.Join(ErrActionHistoryUnavailable, err)
	}
	if err := operation.Err(); err != nil {
		return errors.Join(ErrActionHistoryUnavailable, err)
	}
	if errors.Is(cause, context.Canceled) {
		return errors.Join(ErrActionHistoryUnavailable, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return errors.Join(ErrActionHistoryUnavailable, context.DeadlineExceeded)
	}
	return nil
}

func postgresActionHistoryUnavailable(operation string) error {
	return fmt.Errorf("%w: PostgreSQL witness %s failed", ErrActionHistoryUnavailable, operation)
}

var _ ActionHistoryWitness = (*PostgresActionHistoryWitness)(nil)

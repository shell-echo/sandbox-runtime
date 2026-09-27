// Package providerpostgres supplies the Phase 6 Provider transactional state
// boundary. Provider-local documents share one locked aggregate row so a
// mutation is serialized across controllers and either commits completely or
// remains invisible. The documents remain Provider evidence, never caller
// business truth.
package providerpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	minOperationTimeout    = 10 * time.Millisecond
	maxOperationTimeout    = 30 * time.Second
	maxDocumentBytes       = 64 << 20
	maxStoredDocumentBytes = (maxDocumentBytes+2)/3*4 + 2
)

var (
	ErrUnavailable = errors.New("Provider transactional state is unavailable")
	ErrCorrupt     = errors.New("Provider transactional state is corrupt")
	ErrClosed      = errors.New("Provider transactional state is closed")
)

type Store struct {
	pool             *pgxpool.Pool
	operationTimeout time.Duration
}

func New(pool *pgxpool.Pool, operationTimeout time.Duration) (*Store, error) {
	if pool == nil || operationTimeout < minOperationTimeout || operationTimeout > maxOperationTimeout {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, operationTimeout: operationTimeout}, nil
}

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	if err := s.pool.Ping(opCtx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Close() error { return nil }

func readState[T any](ctx context.Context, store *Store, key string, fresh func() T, importState func(*T, json.RawMessage) error) (T, error) {
	state := fresh()
	if store == nil || store.pool == nil || ctx == nil || key == "" {
		return state, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var document []byte
	if err := store.pool.QueryRow(opCtx, `SELECT documents->$1 FROM sandbox_runtime_provider.control_state WHERE singleton`, key).Scan(&document); err != nil {
		return state, stateError(ctx, opCtx, err)
	}
	decoded, exists, err := decodeStoredDocument(document)
	if err != nil {
		return fresh(), err
	}
	if !exists {
		return state, nil
	}
	if importState(&state, decoded) != nil {
		return fresh(), ErrCorrupt
	}
	return state, nil
}

func mutateState[T any](ctx context.Context, store *Store, key string, fresh func() T, importState func(*T, json.RawMessage) error, exportState func(T) any, mutation func(*T) error) error {
	if store == nil || store.pool == nil || ctx == nil || key == "" || mutation == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	// The singleton row lock is the cross-controller serialization point. Read
	// committed avoids surfacing serialization retries to domain repositories;
	// every contender observes the previous committed document after the lock.
	tx, err := store.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return stateError(ctx, opCtx, err)
	}
	defer rollbackBounded(tx, store.operationTimeout)
	var document []byte
	if err := tx.QueryRow(opCtx, `SELECT documents->$1 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`, key).Scan(&document); err != nil {
		return stateError(ctx, opCtx, err)
	}
	state := fresh()
	decoded, exists, err := decodeStoredDocument(document)
	if err != nil {
		return err
	}
	if exists {
		if importState(&state, decoded) != nil {
			return ErrCorrupt
		}
	}
	if err := mutation(&state); err != nil {
		return err
	}
	encoded, err := json.Marshal(exportState(state))
	if err != nil || len(encoded) > maxDocumentBytes {
		return ErrCorrupt
	}
	// PostgreSQL jsonb rejects the otherwise valid JSON escape \u0000. Some
	// established Provider repositories deliberately use NUL separators in
	// private scope keys, so preserve the exact JSON bytes as one bounded
	// base64 string rather than changing domain persistence semantics.
	stored, err := json.Marshal(base64.StdEncoding.EncodeToString(encoded))
	if err != nil || len(stored) > maxStoredDocumentBytes {
		return ErrCorrupt
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state
SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true),revision=revision+1,updated_at=clock_timestamp()
WHERE singleton`, key, stored); err != nil {
		return stateError(ctx, opCtx, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return stateError(ctx, opCtx, err)
	}
	return nil
}

// mutateStatePair locks the single Provider authority row while checking and
// changing two documents. Browser handoff binding needs the current session
// and sandbox fence to be checked in the same transaction as its reference
// update; two separate repository calls would permit a stale bind race.
func mutateStatePair[A, B any](ctx context.Context, store *Store,
	firstKey, secondKey string, freshFirst func() A, importFirst func(*A, json.RawMessage) error, exportFirst func(A) any,
	freshSecond func() B, importSecond func(*B, json.RawMessage) error, exportSecond func(B) any,
	mutation func(*A, *B) error,
) error {
	if store == nil || store.pool == nil || ctx == nil || firstKey == "" || secondKey == "" || firstKey == secondKey || mutation == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return stateError(ctx, opCtx, err)
	}
	defer rollbackBounded(tx, store.operationTimeout)
	var firstDocument, secondDocument []byte
	if err := tx.QueryRow(opCtx, `SELECT documents->$1,documents->$2 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`, firstKey, secondKey).Scan(&firstDocument, &secondDocument); err != nil {
		return stateError(ctx, opCtx, err)
	}
	first, second := freshFirst(), freshSecond()
	firstDecoded, firstExists, err := decodeStoredDocument(firstDocument)
	if err != nil {
		return err
	}
	secondDecoded, secondExists, err := decodeStoredDocument(secondDocument)
	if err != nil {
		return err
	}
	if firstExists && importFirst(&first, firstDecoded) != nil || secondExists && importSecond(&second, secondDecoded) != nil {
		return ErrCorrupt
	}
	if err := mutation(&first, &second); err != nil {
		return err
	}
	firstStored, err := encodeStoredState(exportFirst(first))
	if err != nil {
		return err
	}
	secondStored, err := encodeStoredState(exportSecond(second))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state
SET documents=jsonb_set(jsonb_set(documents,ARRAY[$1]::text[],$3::jsonb,true),ARRAY[$2]::text[],$4::jsonb,true),revision=revision+1,updated_at=clock_timestamp()
WHERE singleton`, firstKey, secondKey, firstStored, secondStored); err != nil {
		return stateError(ctx, opCtx, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return stateError(ctx, opCtx, err)
	}
	return nil
}

// mutateStateTriple composes the initialized identity marker, finite slot
// state and Browser session authority under the same Provider row lock. No
// runtime or Docker I/O is permitted inside this transaction.
func mutateStateTriple[A, B, C any](ctx context.Context, store *Store,
	firstKey, secondKey, thirdKey string,
	freshFirst func() A, importFirst func(*A, json.RawMessage) error, exportFirst func(A) any,
	freshSecond func() B, importSecond func(*B, json.RawMessage) error, exportSecond func(B) any,
	freshThird func() C, importThird func(*C, json.RawMessage) error, exportThird func(C) any,
	mutation func(*A, *B, *C) error,
) error {
	if store == nil || store.pool == nil || ctx == nil || firstKey == "" || secondKey == "" || thirdKey == "" ||
		firstKey == secondKey || firstKey == thirdKey || secondKey == thirdKey || mutation == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return stateError(ctx, opCtx, err)
	}
	defer rollbackBounded(tx, store.operationTimeout)
	var firstDocument, secondDocument, thirdDocument []byte
	if err := tx.QueryRow(opCtx, `SELECT documents->$1,documents->$2,documents->$3 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`,
		firstKey, secondKey, thirdKey).Scan(&firstDocument, &secondDocument, &thirdDocument); err != nil {
		return stateError(ctx, opCtx, err)
	}
	first, second, third := freshFirst(), freshSecond(), freshThird()
	for _, item := range []struct {
		document []byte
		imported func(json.RawMessage) error
	}{
		{firstDocument, func(value json.RawMessage) error { return importFirst(&first, value) }},
		{secondDocument, func(value json.RawMessage) error { return importSecond(&second, value) }},
		{thirdDocument, func(value json.RawMessage) error { return importThird(&third, value) }},
	} {
		decoded, exists, err := decodeStoredDocument(item.document)
		if err != nil {
			return err
		}
		if exists && item.imported(decoded) != nil {
			return ErrCorrupt
		}
	}
	if err := mutation(&first, &second, &third); err != nil {
		return err
	}
	firstStored, err := encodeStoredState(exportFirst(first))
	if err != nil {
		return err
	}
	secondStored, err := encodeStoredState(exportSecond(second))
	if err != nil {
		return err
	}
	thirdStored, err := encodeStoredState(exportThird(third))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state
SET documents=jsonb_set(jsonb_set(jsonb_set(documents,ARRAY[$1]::text[],$4::jsonb,true),ARRAY[$2]::text[],$5::jsonb,true),ARRAY[$3]::text[],$6::jsonb,true),revision=revision+1,updated_at=clock_timestamp()
WHERE singleton`, firstKey, secondKey, thirdKey, firstStored, secondStored, thirdStored); err != nil {
		return stateError(ctx, opCtx, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return stateError(ctx, opCtx, err)
	}
	return nil
}

func encodeStoredState(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxDocumentBytes {
		return nil, ErrCorrupt
	}
	stored, err := json.Marshal(base64.StdEncoding.EncodeToString(encoded))
	if err != nil || len(stored) > maxStoredDocumentBytes {
		return nil, ErrCorrupt
	}
	return stored, nil
}

func decodeStoredDocument(document []byte) (json.RawMessage, bool, error) {
	if len(document) == 0 || string(document) == "null" {
		return nil, false, nil
	}
	if len(document) > maxStoredDocumentBytes {
		return nil, false, ErrCorrupt
	}
	var encoded string
	if err := json.Unmarshal(document, &encoded); err != nil || base64.StdEncoding.DecodedLen(len(encoded)) > maxDocumentBytes {
		return nil, false, ErrCorrupt
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maxDocumentBytes {
		return nil, false, ErrCorrupt
	}
	return decoded, true, nil
}

func decodePersisted[T any](target *T, document json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	return nil
}

func stateError(parent, operation context.Context, cause error) error {
	if parent != nil {
		if err := parent.Err(); err != nil {
			return err
		}
	}
	if operation != nil {
		if err := operation.Err(); err != nil {
			return errors.Join(ErrUnavailable, err)
		}
	}
	_ = cause
	return ErrUnavailable
}

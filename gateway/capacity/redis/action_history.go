package rediscapacity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

const actionHistoryTokenBytes = 32

var (
	ErrActionHistoryNotProvisioned = errors.New("downstream action history witness is not provisioned")
	ErrActionHistoryConflict       = errors.New("downstream action history witness conflict")
	ErrActionHistoryUnavailable    = errors.New("downstream action history witness is unavailable")
	actionHistoryTokenPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ActionHistoryCheckpoint is the private monotonic state shared between a
// witnessed action fencer and an independently durable witness. Its token must
// not be logged, audited, or exposed through caller evidence.
type ActionHistoryCheckpoint struct {
	sequence int64
	token    string
}

func NewActionHistoryCheckpoint(sequence int64, token string) (ActionHistoryCheckpoint, error) {
	checkpoint := ActionHistoryCheckpoint{sequence: sequence, token: token}
	if err := checkpoint.validate(); err != nil {
		return ActionHistoryCheckpoint{}, err
	}
	return checkpoint, nil
}

func (c ActionHistoryCheckpoint) Sequence() int64 { return c.sequence }

// OpaqueToken returns private witness material for trusted persistence and
// action-authority adapters only.
func (c ActionHistoryCheckpoint) OpaqueToken() string { return c.token }

func (c ActionHistoryCheckpoint) Equal(other ActionHistoryCheckpoint) bool {
	return c.sequence == other.sequence && c.token == other.token
}

func (c ActionHistoryCheckpoint) String() string {
	return fmt.Sprintf("action-history-checkpoint(sequence=%d, token=[redacted])", c.sequence)
}

func (c ActionHistoryCheckpoint) GoString() string {
	return fmt.Sprintf("rediscapacity.ActionHistoryCheckpoint{sequence:%d, token:[redacted]}", c.sequence)
}

func (c ActionHistoryCheckpoint) validate() error {
	if c.sequence < 0 || c.sequence > maxLuaExactInteger || !actionHistoryTokenPattern.MatchString(c.token) {
		return ErrActionHistoryUnavailable
	}
	decoded, err := hex.DecodeString(c.token)
	if err != nil || len(decoded) != actionHistoryTokenBytes || hex.EncodeToString(decoded) != c.token {
		return ErrActionHistoryUnavailable
	}
	return nil
}

// ActionHistoryWitness is an independent monotonic checkpoint authority. Its
// storage must not share the Redis-compatible authority's snapshot or restore
// domain. CompareAndSwap must be durable before it returns success.
type ActionHistoryWitness interface {
	Load(context.Context, string) (ActionHistoryCheckpoint, error)
	Provision(context.Context, string, ActionHistoryCheckpoint) error
	CompareAndSwap(context.Context, string, ActionHistoryCheckpoint, ActionHistoryCheckpoint) error
}

func randomActionHistoryToken() (string, error) {
	var token [actionHistoryTokenBytes]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

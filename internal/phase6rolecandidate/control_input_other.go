//go:build !darwin && !linux

package phase6rolecandidate

import (
	"context"
	"io"
)

type candidateFile struct{}

func (*candidateFile) size() int64 { return 0 }

func openCandidateFile(string, int64) (*candidateFile, error) { return nil, ErrInvalidControlCandidate }
func (*candidateFile) copy(context.Context, io.Writer) (string, error) {
	return "", ErrInvalidControlCandidate
}
func (*candidateFile) Close() error { return nil }
func candidateSpace(string) error   { return ErrInvalidControlCandidate }

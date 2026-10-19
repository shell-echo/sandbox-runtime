//go:build !linux

package trustanchor

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var errRetainedDirectory = errors.New("retained trust anchor requires Linux")

type DirectorySession struct{}

func RetainDirectory(context.Context, phase6security.TrustAnchor, time.Time) (*DirectorySession, error) {
	return nil, errRetainedDirectory
}

func (*DirectorySession) Observe(context.Context, time.Time) (DirectoryObservation, error) {
	return DirectoryObservation{}, errRetainedDirectory
}

func (*DirectorySession) Close() error { return nil }

func (*DirectorySession) Roots(context.Context, time.Time) (*x509.CertPool, error) {
	return nil, errRetainedDirectory
}

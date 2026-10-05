// Package artifactscanner contains the private scanner transport and its
// bounded ClamAV adapter. It does not own Provider artifact truth or publish
// artifacts.
package artifactscanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

const (
	clamdChunkBytes    = 64 << 10
	clamdMaxReplyBytes = 1024
	clamdMaxDuration   = 30 * time.Second
)

var ErrClamdUnavailable = errors.New("private malware engine unavailable")

type MalwareVerdict string

const (
	MalwareClean    MalwareVerdict = "clean"
	MalwareInfected MalwareVerdict = "infected"
)

type Clamd struct {
	socketPath string
	layout     restrictedunix.Layout
	dial       func(context.Context, string, string) (net.Conn, error)
}

func (c *Clamd) Ready(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.dial == nil || !restrictedunix.ValidateSocket(c.socketPath, c.layout) {
		return ErrClamdUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, clamdMaxDuration)
	defer cancel()
	connection, err := c.dial(operation, "unix", c.socketPath)
	if err != nil {
		return ErrClamdUnavailable
	}
	defer connection.Close()
	stop := context.AfterFunc(operation, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := operation.Deadline(); ok && connection.SetDeadline(deadline) != nil {
		return ErrClamdUnavailable
	}
	if err := writeClamdAll(connection, []byte("zPING\x00")); err != nil {
		return clamdError(operation, err)
	}
	reply, err := io.ReadAll(io.LimitReader(connection, 16))
	if err != nil || !bytes.Equal(reply, []byte("PONG\x00")) {
		return clamdError(operation, err)
	}
	return operation.Err()
}

func NewClamd(socketPath string, layout restrictedunix.Layout) (*Clamd, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		!restrictedunix.ValidateParent(socketPath, layout) {
		return nil, ErrClamdUnavailable
	}
	return &Clamd{socketPath: socketPath, layout: layout, dial: (&net.Dialer{}).DialContext}, nil
}

// Scan submits exactly one complete byte sequence using ClamD's documented
// NUL-framed INSTREAM command. Only an exact clean reply is clean. Any scan
// limit, socket loss, malformed/multiple reply, or cancellation is unavailable.
func (c *Clamd) Scan(ctx context.Context, content []byte) (MalwareVerdict, error) {
	if ctx == nil {
		return "", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c == nil || c.dial == nil || len(content) == 0 || len(content) > artifact.MaxArtifactBytes ||
		!restrictedunix.ValidateSocket(c.socketPath, c.layout) {
		return "", ErrClamdUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, clamdMaxDuration)
	defer cancel()
	connection, err := c.dial(operation, "unix", c.socketPath)
	if err != nil {
		return "", ErrClamdUnavailable
	}
	defer connection.Close()
	stop := context.AfterFunc(operation, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := operation.Deadline(); ok {
		if connection.SetDeadline(deadline) != nil {
			return "", ErrClamdUnavailable
		}
	}
	if err := writeClamdAll(connection, []byte("zINSTREAM\x00")); err != nil {
		return "", clamdError(operation, err)
	}
	var length [4]byte
	for offset := 0; offset < len(content); {
		if err := operation.Err(); err != nil {
			return "", err
		}
		end := min(offset+clamdChunkBytes, len(content))
		binary.BigEndian.PutUint32(length[:], uint32(end-offset))
		if err := writeClamdAll(connection, length[:]); err != nil {
			return "", clamdError(operation, err)
		}
		if err := writeClamdAll(connection, content[offset:end]); err != nil {
			return "", clamdError(operation, err)
		}
		offset = end
	}
	clear(length[:])
	if err := writeClamdAll(connection, length[:]); err != nil { // zero-length terminator
		return "", clamdError(operation, err)
	}
	reply, err := io.ReadAll(io.LimitReader(connection, clamdMaxReplyBytes+1))
	if err != nil || len(reply) == 0 || len(reply) > clamdMaxReplyBytes {
		return "", clamdError(operation, err)
	}
	if err := operation.Err(); err != nil {
		return "", err
	}
	if bytes.Equal(reply, []byte("stream: OK\x00")) {
		return MalwareClean, nil
	}
	if bytes.HasPrefix(reply, []byte("stream: ")) && bytes.HasSuffix(reply, []byte(" FOUND\x00")) &&
		validSignature(reply[len("stream: "):len(reply)-len(" FOUND\x00")]) {
		return MalwareInfected, nil
	}
	return "", ErrClamdUnavailable
}

func writeClamdAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written < 1 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func clamdError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return errors.Join(ErrClamdUnavailable, err)
}

func validSignature(value []byte) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if char < '!' || char > '~' || char == ':' {
			return false
		}
	}
	return true
}

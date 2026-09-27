// Package browsercdp translates bounded logical CDP text messages to the
// already-upgraded WebSocket wire returned by the Provider-owned Docker
// Browser runtime. It does not select or authorize a runtime target.
package browsercdp

import (
	"context"
	"errors"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

const MaxMessageBytes = 256 << 10

var ErrInvalidFrame = errors.New("invalid Browser CDP frame")

type Stream interface {
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

type Conn struct {
	stream    Stream
	reader    *wsutil.Reader
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func New(stream Stream) (*Conn, error) {
	if stream == nil {
		return nil, ErrInvalidFrame
	}
	reader := wsutil.NewClientSideReader(nil)
	reader.CheckUTF8 = true
	reader.MaxFrameSize = MaxMessageBytes
	return &Conn{stream: stream, reader: reader}, nil
}

func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	if c == nil || ctx == nil || c.stream == nil {
		return nil, ErrInvalidFrame
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.reader.Source = streamReader{ctx: ctx, stream: c.stream}
	c.reader.OnIntermediate = wsutil.ControlFrameHandler(streamWriter{ctx: ctx, conn: c}, ws.StateClientSide)
	for {
		header, err := c.reader.NextFrame()
		if err != nil {
			return nil, err
		}
		if header.OpCode.IsControl() {
			if header.OpCode == ws.OpClose {
				return nil, io.EOF
			}
			if err := wsutil.ControlFrameHandler(streamWriter{ctx: ctx, conn: c}, ws.StateClientSide)(header, c.reader); err != nil {
				return nil, err
			}
			continue
		}
		if header.OpCode != ws.OpText {
			return nil, ErrInvalidFrame
		}
		payload, err := io.ReadAll(io.LimitReader(c.reader, MaxMessageBytes+1))
		if err != nil || len(payload) == 0 || len(payload) > MaxMessageBytes || !utf8.Valid(payload) {
			return nil, ErrInvalidFrame
		}
		return payload, nil
	}
}

func (c *Conn) Write(ctx context.Context, payload []byte) error {
	if c == nil || ctx == nil || c.stream == nil || len(payload) == 0 || len(payload) > MaxMessageBytes || !utf8.Valid(payload) {
		return ErrInvalidFrame
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return wsutil.WriteClientText(rawWriter{ctx: ctx, stream: c.stream}, payload)
}

func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() { c.closeErr = c.stream.Close() })
	return c.closeErr
}

type streamReader struct {
	ctx    context.Context
	stream Stream
}

func (r streamReader) Read(p []byte) (int, error) { return r.stream.Read(r.ctx, p) }

type rawWriter struct {
	ctx    context.Context
	stream Stream
}

func (w rawWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.stream.Write(w.ctx, p)
		if n < 0 || n > len(p) {
			return total, io.ErrShortWrite
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

type streamWriter struct {
	ctx  context.Context
	conn *Conn
}

func (w streamWriter) Write(p []byte) (int, error) {
	w.conn.writeMu.Lock()
	defer w.conn.writeMu.Unlock()
	return rawWriter{ctx: w.ctx, stream: w.conn.stream}.Write(p)
}

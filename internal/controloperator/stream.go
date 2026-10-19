package controloperator

import (
	"encoding/binary"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"io"
)

// dockerStdout strictly demultiplexes non-TTY Docker frames. Stderr can never
// be parsed as the challenge or receipt, and all channels are bounded.
type dockerStdout struct {
	r         io.Reader
	remaining uint32
	total     int
	stderr    []byte
}

func (d *dockerStdout) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if d.remaining > 0 {
			n := len(b)
			if uint32(n) > d.remaining {
				n = int(d.remaining)
			}
			n, e := io.ReadFull(d.r, b[:n])
			d.remaining -= uint32(n)
			return n, e
		}
		var h [8]byte
		n, e := io.ReadFull(d.r, h[:])
		if n == 0 && e == io.EOF {
			return 0, io.EOF
		}
		if e != nil || h[1] != 0 || h[2] != 0 || h[3] != 0 || (h[0] != 1 && h[0] != 2) {
			return 0, controldelivery.ErrUnavailable
		}
		size := binary.BigEndian.Uint32(h[4:])
		if size == 0 || size > controldelivery.MaxFrame || d.total+int(size) > 4*controldelivery.MaxFrame {
			return 0, controldelivery.ErrUnavailable
		}
		d.total += int(size)
		if h[0] == 1 {
			d.remaining = size
			continue
		}
		if len(d.stderr)+int(size) > 4096 {
			return 0, controldelivery.ErrUnavailable
		}
		part := make([]byte, int(size))
		if _, e := io.ReadFull(d.r, part); e != nil {
			return 0, controldelivery.ErrUnavailable
		}
		d.stderr = append(d.stderr, part...)
	}
}

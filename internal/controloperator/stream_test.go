package controloperator

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func mux(channel byte, data []byte) []byte {
	h := make([]byte, 8)
	h[0] = channel
	binary.BigEndian.PutUint32(h[4:], uint32(len(data)))
	return append(h, data...)
}
func TestDockerStreamNeverTreatsStderrAsProtocol(t *testing.T) {
	input := append(mux(2, []byte("fake receipt")), mux(1, []byte("actual stdout"))...)
	d := &dockerStdout{r: bytes.NewReader(input)}
	b, e := io.ReadAll(d)
	if e != nil || string(b) != "actual stdout" || string(d.stderr) != "fake receipt" {
		t.Fatal("demultiplexing")
	}
	for name, raw := range map[string][]byte{"truncated": {1, 0}, "reserved": {1, 1, 0, 0, 0, 0, 0, 1, 1}, "stdin": mux(0, []byte("x")), "daemon error": mux(3, []byte("x")), "oversized": {1, 0, 0, 0, 255, 255, 255, 255}, "truncated content": {1, 0, 0, 0, 0, 0, 0, 4, 1}, "stderr bound": mux(2, make([]byte, 4097))} {
		t.Run(name, func(t *testing.T) {
			if _, e := io.ReadAll(&dockerStdout{r: bytes.NewReader(raw)}); e == nil {
				t.Fatal("bad stream")
			}
		})
	}
}

package browsercdp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type memoryStream struct {
	read    *bytes.Reader
	written bytes.Buffer
	closed  bool
}

func (s *memoryStream) Read(_ context.Context, p []byte) (int, error)  { return s.read.Read(p) }
func (s *memoryStream) Write(_ context.Context, p []byte) (int, error) { return s.written.Write(p) }
func (s *memoryStream) Close() error                                   { s.closed = true; return nil }

func TestCDPWireTextRoundTripAndClose(t *testing.T) {
	var inbound bytes.Buffer
	if err := wsutil.WriteServerText(&inbound, []byte(`{"id":1,"result":{}}`)); err != nil {
		t.Fatal(err)
	}
	stream := &memoryStream{read: bytes.NewReader(inbound.Bytes())}
	connection, err := New(stream)
	if err != nil {
		t.Fatal(err)
	}
	response, err := connection.Read(context.Background())
	if err != nil || string(response) != `{"id":1,"result":{}}` {
		t.Fatalf("CDP response = %q, %v", response, err)
	}
	if err := connection.Write(context.Background(), []byte(`{"id":1,"method":"Browser.getVersion"}`)); err != nil {
		t.Fatal(err)
	}
	request, opcode, err := wsutil.ReadClientData(&stream.written)
	if err != nil || opcode != ws.OpText || string(request) != `{"id":1,"method":"Browser.getVersion"}` {
		t.Fatalf("CDP request = %q, %v, %v", request, opcode, err)
	}
	if err := connection.Close(); err != nil || !stream.closed {
		t.Fatalf("CDP close: %v", err)
	}
}

func TestCDPWireRejectsBinaryOversizeAndMalformedUTF8(t *testing.T) {
	for name, frame := range map[string]func(io.Writer) error{
		"binary": func(w io.Writer) error { return wsutil.WriteServerBinary(w, []byte("opaque")) },
		"oversize": func(w io.Writer) error {
			return wsutil.WriteServerText(w, bytes.Repeat([]byte("x"), MaxMessageBytes+1))
		},
		"utf8": func(w io.Writer) error { return wsutil.WriteServerText(w, []byte{0xff}) },
	} {
		t.Run(name, func(t *testing.T) {
			var inbound bytes.Buffer
			if err := frame(&inbound); err != nil {
				t.Fatal(err)
			}
			connection, err := New(&memoryStream{read: bytes.NewReader(inbound.Bytes())})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Read(context.Background()); err == nil {
				t.Fatal("unsafe CDP frame accepted")
			}
		})
	}
	connection, err := New(&memoryStream{read: bytes.NewReader(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), bytes.Repeat([]byte("x"), MaxMessageBytes+1)); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversized outbound CDP frame accepted: %v", err)
	}
}
